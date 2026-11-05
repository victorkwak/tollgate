//! Sticky verify checkouts (R41-R44, R87, L15).
//!
//! L15: each agent worktree gets its own checkout per tier at
//! `<verify root>/<repo key>/<tier>/<worktree key>`, created on first use
//! as a registered, locked git worktree, so its incremental build stays
//! warm. Above `verify.max_checkouts` (`max_full_checkouts` for `full`)
//! the least recently used checkout whose lock is free is removed. The
//! checkout lock (R87) is held for the whole job.
//!
//! Before a job (R42): `read-tree -u --reset <T>`, `clean -ffdx` keeping
//! `target`, `node_modules`, `.venv` and the steps' `cache_dirs`, then no
//! untracked file and no index/worktree difference may be left, and
//! `write-tree` must equal `T`. After each step, no tracked file, index
//! entry or untracked file may have changed ([`Checkout::changes`]).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::Tier;
use crate::fsx;
use crate::gitx::{Git, GitError, Oid};
use crate::ids::{RepoKey, WorktreeKey};
use crate::locks::LockFile;
use crate::runner::env::JobEnv;

/// Dirs `git clean` keeps in every checkout (R42, R43).
pub const KEEP_DIRS: &[&str] = &["target", "node_modules", ".venv"];

/// Entries [`Checkout::check_links`] reads under link targets that are not
/// tree content before it gives up (and refuses).
const LINK_WALK_BUDGET: usize = 20_000;

/// Metadata next to a checkout (L15 LRU, R45 setup state).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckoutMeta {
    /// The agent worktree the checkout belongs to.
    pub origin: PathBuf,
    /// The repo's common dir (gc removes checkouts of gone repos, R48).
    pub common_dir: PathBuf,
    /// Tier.
    pub tier: Tier,
    /// Creation.
    pub created: jiff::Timestamp,
    /// Last job start (LRU).
    pub last_used: jiff::Timestamp,
    /// Setup step name -> input hash of its last successful run (R45).
    #[serde(default)]
    pub setup: std::collections::BTreeMap<String, String>,
}

impl CheckoutMeta {
    /// Reads a meta file.
    #[must_use]
    pub fn read(path: &Path) -> Option<Self> {
        let bytes = fsx::read_optional(path).ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    /// Writes it by atomic rename.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        fsx::write_atomic(
            path,
            &serde_json::to_vec_pretty(self).map_err(io::Error::other)?,
        )
    }
}

/// Error from checkout handling.
#[derive(Debug, thiserror::Error)]
pub enum CheckoutError {
    /// File system.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// git.
    #[error(transparent)]
    Git(#[from] GitError),
    /// The checkout does not hold `T` (R42).
    #[error("{0}")]
    Mismatch(String),
}

/// Where a job's checkout lives.
#[derive(Debug, Clone)]
pub struct Place {
    /// `<verify root>/<repo>/<tier>`.
    pub tier_dir: PathBuf,
    /// The checkout dir.
    pub path: PathBuf,
    /// Its lock (R87).
    pub lock: PathBuf,
    /// Its meta file.
    pub meta: PathBuf,
}

impl Place {
    /// The place of the checkout of `origin` (realpath of the agent
    /// worktree) for `tier`.
    #[must_use]
    pub fn new(verify_root: &Path, repo: &RepoKey, tier: Tier, origin: &Path) -> Self {
        let wt = WorktreeKey::of_realpath(origin);
        Self {
            tier_dir: crate::dirs::verify_tier_dir(verify_root, repo, tier),
            path: crate::dirs::verify_checkout(verify_root, repo, tier, &wt),
            lock: crate::dirs::verify_checkout_lock(verify_root, repo, tier, &wt),
            meta: crate::dirs::verify_checkout_meta(verify_root, repo, tier, &wt),
        }
    }
}

/// Why waiting for the checkout lock stopped.
#[derive(Debug)]
pub enum LockWait {
    /// The deadline passed (R33 queue budget).
    Deadline,
    /// The abort callback stopped it.
    Aborted(String),
    /// The lock file failed.
    Io(io::Error),
}

/// Takes the checkout lock, polling until `deadline` (R33, R87).
pub fn lock(
    place: &Place,
    deadline: Instant,
    abort: &mut dyn FnMut() -> Option<String>,
) -> Result<LockFile, LockWait> {
    loop {
        if let Some(r) = abort() {
            return Err(LockWait::Aborted(r));
        }
        match LockFile::try_acquire(&place.lock) {
            Ok(Some(l)) => return Ok(l),
            Ok(None) => {}
            Err(e) => return Err(LockWait::Io(e)),
        }
        if Instant::now() >= deadline {
            return Err(LockWait::Deadline);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A checkout whose lock the job holds.
#[derive(Debug)]
pub struct Checkout {
    /// Worktree dir.
    pub path: PathBuf,
    /// Its git dir (`<common>/worktrees/<name>`).
    pub git_dir: PathBuf,
    /// Meta file.
    pub meta_path: PathBuf,
    _lock: LockFile,
}

/// The git dir named by `<path>/.git`, when the checkout is a live worktree
/// of `common_dir`.
fn registered_git_dir(path: &Path, common_dir: &Path) -> Option<PathBuf> {
    let text = fs::read_to_string(path.join(".git")).ok()?;
    let gd = PathBuf::from(text.strip_prefix("gitdir:")?.trim());
    let back = fs::read_to_string(gd.join("gitdir")).ok()?;
    let back = fs::canonicalize(back.trim()).ok()?;
    if back != fs::canonicalize(path.join(".git")).ok()? {
        return None;
    }
    let common = fs::read_to_string(gd.join("commondir")).ok()?;
    let common = gd.join(common.trim());
    (fs::canonicalize(common).ok()? == fs::canonicalize(common_dir).ok()?).then_some(gd)
}

/// Removes a checkout: unlock and remove the worktree, or delete the dir
/// and prune when git cannot.
pub fn remove(repo_git: &Git, path: &Path, meta: &Path) {
    let p = path.as_os_str();
    let _ = repo_git.output([
        std::ffi::OsStr::new("worktree"),
        std::ffi::OsStr::new("unlock"),
        p,
    ]);
    let removed = repo_git
        .output([
            std::ffi::OsStr::new("worktree"),
            std::ffi::OsStr::new("remove"),
            std::ffi::OsStr::new("--force"),
            std::ffi::OsStr::new("--force"),
            p,
        ])
        .is_ok_and(|o| o.status.success());
    if !removed || path.exists() {
        let _ = fs::remove_dir_all(path);
        let _ = repo_git.output(["worktree", "prune"]);
    }
    let _ = fs::remove_file(meta);
}

/// L15: removes least recently used checkouts of the tier until fewer than
/// `max` remain (so one more fits). Checkouts in use are skipped.
fn evict(repo_git: &Git, place: &Place, max: u32) -> io::Result<()> {
    let mut others: Vec<(jiff::Timestamp, PathBuf)> = Vec::new();
    let rd = match fs::read_dir(&place.tier_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in rd.flatten() {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "json") && p != place.meta {
            let used = CheckoutMeta::read(&p).map_or(jiff::Timestamp::UNIX_EPOCH, |m| m.last_used);
            others.push((used, p));
        }
    }
    others.sort();
    let mut count = others.len();
    for (_, meta) in others {
        if count < max as usize {
            break;
        }
        let dir = meta.with_extension("");
        let lock = meta.with_extension("lock");
        let Ok(Some(_held)) = LockFile::try_acquire(&lock) else {
            continue;
        };
        remove(repo_git, &dir, &meta);
        count -= 1;
    }
    Ok(())
}

/// What [`prepare`] needs.
#[derive(Debug, Clone, Copy)]
pub struct PrepareInput<'a> {
    /// Scrubbed git in the agent's repo (R52).
    pub repo_git: &'a Git,
    /// The repo's common dir.
    pub common_dir: &'a Path,
    /// The agent worktree.
    pub origin: &'a Path,
    /// Tier.
    pub tier: Tier,
    /// L15 limit for the tier.
    pub max_checkouts: u32,
}

fn anchor_commit(git: &Git) -> Result<Oid, GitError> {
    if let Some(head) = git.rev_parse_verify("HEAD^{commit}")? {
        return Ok(head);
    }
    // R41: an unborn repo: a dangling commit of the empty tree.
    let empty = git.run_line(["mktree"])?;
    let out = git.run_line([
        "-c",
        "user.name=tollgate",
        "-c",
        "user.email=tollgate@localhost",
        "commit-tree",
        empty.as_str(),
        "-m",
        "tollgate verify checkout anchor",
    ])?;
    Oid::parse(&out).map_err(|detail| GitError::Output {
        args: "commit-tree".into(),
        detail,
    })
}

/// Opens the checkout for a job that holds `lock`: reuses a live one, or
/// creates it (after LRU eviction) with `git worktree add --detach
/// --no-checkout --lock` (R41).
pub fn prepare(
    input: &PrepareInput<'_>,
    place: &Place,
    lock: LockFile,
) -> Result<Checkout, CheckoutError> {
    let now = jiff::Timestamp::now();
    let mut meta = CheckoutMeta::read(&place.meta).unwrap_or(CheckoutMeta {
        origin: input.origin.to_owned(),
        common_dir: input.common_dir.to_owned(),
        tier: input.tier,
        created: now,
        last_used: now,
        setup: Default::default(),
    });
    let git_dir = match registered_git_dir(&place.path, input.common_dir) {
        Some(gd) => gd,
        None => {
            if place.path.exists() {
                remove(input.repo_git, &place.path, &place.meta);
            }
            evict(input.repo_git, place, input.max_checkouts)?;
            fsx::ensure_dir(&place.tier_dir)?;
            let anchor = anchor_commit(input.repo_git)?;
            input.repo_git.run([
                std::ffi::OsStr::new("worktree"),
                std::ffi::OsStr::new("add"),
                std::ffi::OsStr::new("--detach"),
                std::ffi::OsStr::new("--no-checkout"),
                std::ffi::OsStr::new("--lock"),
                std::ffi::OsStr::new("--reason"),
                std::ffi::OsStr::new("tollgate"),
                place.path.as_os_str(),
                std::ffi::OsStr::new(anchor.as_str()),
            ])?;
            meta.created = now;
            meta.setup.clear();
            registered_git_dir(&place.path, input.common_dir).ok_or_else(|| {
                CheckoutError::Mismatch(format!(
                    "{} is not a registered worktree after git worktree add",
                    place.path.display()
                ))
            })?
        }
    };
    meta.last_used = now;
    meta.write(&place.meta)?;
    Ok(Checkout {
        path: fs::canonicalize(&place.path)?,
        git_dir,
        meta_path: place.meta.clone(),
        _lock: lock,
    })
}

fn nul_list(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

impl Checkout {
    /// git in the checkout with the job environment and explicit
    /// `GIT_DIR`, `GIT_WORK_TREE`, `GIT_INDEX_FILE` (R52).
    #[must_use]
    pub fn git(&self, env: &JobEnv) -> Git {
        Git::for_checkout(env, &self.path, &self.git_dir, &self.git_dir.join("index"))
    }

    /// The checkout lock's fd, for processes that must keep the lock held
    /// while they live (R87).
    #[must_use]
    pub fn lock_fd(&self) -> std::os::fd::RawFd {
        use std::os::fd::AsRawFd as _;
        self._lock.file().as_raw_fd()
    }

    /// The meta file content.
    #[must_use]
    pub fn meta(&self) -> Option<CheckoutMeta> {
        CheckoutMeta::read(&self.meta_path)
    }

    /// R42: makes the checkout hold exactly `tree`, keeping build dirs.
    pub fn update(
        &self,
        env: &JobEnv,
        tree: &Oid,
        cache_dirs: &[String],
    ) -> Result<(), CheckoutError> {
        let git = self.git(env);
        git.run(["read-tree", "-u", "--reset", tree.as_str()])?;
        let keep: Vec<&str> = KEEP_DIRS
            .iter()
            .copied()
            .chain(cache_dirs.iter().map(String::as_str))
            .collect();
        let mut clean = vec!["clean".to_owned(), "-ffdxq".to_owned()];
        let mut others = vec![
            "ls-files".to_owned(),
            "--others".to_owned(),
            "--exclude-standard".to_owned(),
            "--directory".to_owned(),
            "-z".to_owned(),
        ];
        for k in &keep {
            clean.push(format!("--exclude={k}"));
            others.push(format!("--exclude={k}"));
        }
        git.run(&clean)?;
        let left = nul_list(&git.run(&others)?);
        if !left.is_empty() {
            return Err(CheckoutError::Mismatch(format!(
                "untracked files left after clean: {}",
                left.join(", ")
            )));
        }
        let changed = self.tracked_changes(env)?;
        if !changed.is_empty() {
            return Err(CheckoutError::Mismatch(format!(
                "files differ from the index after read-tree: {}",
                changed.join(", ")
            )));
        }
        let written = git.write_tree()?;
        if &written != tree {
            return Err(CheckoutError::Mismatch(format!(
                "write-tree gives {written}, expected {tree}"
            )));
        }
        Ok(())
    }

    /// Untracked, non-ignored files outside the kept dirs (R42), one path
    /// per file.
    pub fn untracked(
        &self,
        env: &JobEnv,
        cache_dirs: &[String],
    ) -> Result<std::collections::BTreeSet<String>, CheckoutError> {
        let mut args = vec![
            "ls-files".to_owned(),
            "--others".to_owned(),
            "--exclude-standard".to_owned(),
            "-z".to_owned(),
        ];
        for k in KEEP_DIRS
            .iter()
            .copied()
            .chain(cache_dirs.iter().map(String::as_str))
        {
            args.push(format!("--exclude={k}"));
        }
        Ok(nul_list(&self.git(env).run(&args)?).into_iter().collect())
    }

    /// R42 after a step: tracked files whose content differs from the
    /// index, index entries that differ from `tree` (a step ran `git add`),
    /// and untracked files that were not in `before`. Paths in `allowed`
    /// (the R71 tool configs the job itself replaced) do not count.
    pub fn changes(
        &self,
        env: &JobEnv,
        tree: &Oid,
        cache_dirs: &[String],
        before: &std::collections::BTreeSet<String>,
        allowed: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<String>, CheckoutError> {
        let git = self.git(env);
        let mut changed: std::collections::BTreeSet<String> =
            self.tracked_changes(env)?.into_iter().collect();
        changed.extend(nul_list(&git.run([
            "diff-index",
            "--cached",
            "--name-only",
            "-z",
            tree.as_str(),
        ])?));
        changed.extend(
            self.untracked(env, cache_dirs)?
                .into_iter()
                .filter(|p| !before.contains(p)),
        );
        Ok(changed
            .into_iter()
            .filter(|p| {
                !allowed.contains(p)
                    && !allowed
                        .iter()
                        .any(|a| p.ends_with('/') && a.starts_with(p.as_str()))
            })
            .collect())
    }

    /// Tracked files whose content differs from the index.
    pub fn tracked_changes(&self, env: &JobEnv) -> Result<Vec<String>, CheckoutError> {
        let git = self.git(env);
        // Refresh stat data first so only real content changes count.
        let _ = git.output(["update-index", "-q", "--refresh"]);
        Ok(nul_list(&git.run(["diff-files", "--name-only", "-z"])?))
    }

    /// R71: writes the policy commit's version of each tool config into the
    /// checkout (or removes the tree's), after [`Checkout::update`]. The
    /// next update's `read-tree --reset` and `clean` undo it.
    pub fn apply_overlay(
        &self,
        overlay: &std::collections::BTreeMap<PathBuf, crate::policy::OverlayFile>,
    ) -> Result<(), CheckoutError> {
        use crate::policy::OverlayFile;
        for (rel, file) in overlay {
            if !rel
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                return Err(CheckoutError::Mismatch(format!(
                    "tool config path {} leaves the checkout",
                    rel.display()
                )));
            }
            let path = self.path.join(rel);
            // Never follow a symlinked parent out of the checkout.
            let mut dir = self.path.clone();
            for c in rel.parent().into_iter().flat_map(Path::components) {
                dir.push(c);
                if dir
                    .symlink_metadata()
                    .is_ok_and(|m| m.file_type().is_symlink())
                {
                    fs::remove_file(&dir)?;
                }
            }
            match path.symlink_metadata() {
                Ok(m) if m.is_dir() => fs::remove_dir_all(&path)?,
                Ok(_) => fs::remove_file(&path)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            match file {
                OverlayFile::Absent => {}
                OverlayFile::File { text, executable } => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&path, text)?;
                    if *executable {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                    }
                }
                OverlayFile::Symlink { target } => {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    std::os::unix::fs::symlink(target, &path)?;
                }
            }
        }
        Ok(())
    }

    /// R71 after the overlay: refuses a tool config reached through a
    /// symlink among `links` (the tree's symlinks and the overlay's): a
    /// symlinked tool config, a `.cargo` symlink whose target holds cargo
    /// config, and a dir symlink whose target is not tree content (outside
    /// the checkout, or in a kept dir such as `target/`) and holds a file
    /// with a tool-config name. The policy commit's own links count too:
    /// the branch can change what they point at. A dir link inside the
    /// checkout's tree content needs no walk: every tool config there is a
    /// tree path, and the overlay already set it.
    pub fn check_links<'p>(
        &self,
        links: impl IntoIterator<Item = &'p Path>,
        cache_dirs: &[String],
    ) -> Result<(), CheckoutError> {
        let mut budget = LINK_WALK_BUDGET;
        let mut seen = std::collections::BTreeSet::new();
        for rel in links {
            let p = self.path.join(rel);
            if !p
                .symlink_metadata()
                .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            let refuse = |why: String| {
                Err(CheckoutError::Mismatch(format!(
                    "{} {why} (R71: a tool config must be a regular file in the tree)",
                    rel.display()
                )))
            };
            let cargo_dir = rel.file_name() == Some(std::ffi::OsStr::new(".cargo"));
            if crate::policy::is_tool_config(rel) && !cargo_dir {
                return refuse("is a symlink".into());
            }
            // A dangling link or a link to a file reaches no config dir.
            let Ok(target) = fs::canonicalize(&p) else {
                continue;
            };
            if !target.is_dir() {
                continue;
            }
            if cargo_dir && ["config.toml", "config"].iter().any(|c| p.join(c).exists()) {
                return refuse("links to a dir that holds cargo config".into());
            }
            if let Some(found) = self.foreign_config(&target, cache_dirs, &mut budget, &mut seen)? {
                return refuse(format!(
                    "links to {}, which is not tree content and holds the tool config {}",
                    target.display(),
                    found.display()
                ));
            }
        }
        Ok(())
    }

    /// True when canonical `path` is tree content: inside the checkout and
    /// in no kept dir (after [`Checkout::update`] nothing else is there).
    fn tree_content(&self, path: &Path, cache_dirs: &[String]) -> bool {
        let Ok(rel) = path.strip_prefix(&self.path) else {
            return false;
        };
        !rel.components().any(|c| {
            let c = c.as_os_str();
            KEEP_DIRS.iter().any(|k| c == *k)
                || cache_dirs
                    .iter()
                    .any(|d| c == d.as_str() || rel.starts_with(d.trim_end_matches('/')))
        })
    }

    /// A file under `dir` (not tree content) whose name a tool looks for
    /// (`clippy.toml`, `rustfmt.toml`, `.cargo/config.toml`, ...), walking
    /// nested dir links the same way; a walk over `budget` entries counts
    /// as found (fail closed).
    fn foreign_config(
        &self,
        dir: &Path,
        cache_dirs: &[String],
        budget: &mut usize,
        seen: &mut std::collections::BTreeSet<PathBuf>,
    ) -> Result<Option<PathBuf>, CheckoutError> {
        if self.tree_content(dir, cache_dirs) || !seen.insert(dir.to_owned()) {
            return Ok(None);
        }
        let mut stack = vec![dir.to_owned()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                if *budget == 0 {
                    return Ok(Some(d.join("...")));
                }
                *budget -= 1;
                let p = e.path();
                let Ok(md) = p.symlink_metadata() else {
                    continue;
                };
                let rel = p.strip_prefix(dir).unwrap_or(&p);
                if crate::policy::is_tool_config(rel)
                    || crate::policy::is_tool_config(Path::new(&e.file_name()))
                {
                    return Ok(Some(p));
                }
                if md.is_dir() {
                    stack.push(p);
                } else if md.file_type().is_symlink()
                    && let Ok(t) = fs::canonicalize(&p)
                    && t.is_dir()
                    && let Some(f) = self.foreign_config(&t, cache_dirs, budget, seen)?
                {
                    return Ok(Some(f));
                }
            }
        }
        Ok(None)
    }

    /// Updates the meta file with `f`.
    pub fn update_meta(&self, f: impl FnOnce(&mut CheckoutMeta)) -> io::Result<()> {
        if let Some(mut m) = self.meta() {
            f(&mut m);
            m.write(&self.meta_path)?;
        }
        Ok(())
    }
}

/// Free bytes for unprivileged users on the file system of `path` (R44).
pub fn free_bytes(path: &Path) -> io::Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    // SAFETY: statvfs is plain old data; zeroed is valid and statvfs fills it.
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated path and `st` a writable statvfs.
    if unsafe { libc::statvfs(c.as_ptr(), &raw mut st) } != 0 {
        return Err(io::Error::last_os_error());
    }
    #[allow(clippy::useless_conversion)]
    let bytes = u64::from(st.f_bavail).saturating_mul(u64::from(st.f_frsize));
    Ok(bytes)
}

/// R44, first pass: removes the build outputs in the cargo target dir
/// `target` of packages that are not in `current` (every package name of
/// the workspace's resolve graph): a removed member or a dropped
/// dependency. `cargo clean -p` cannot do it, since it accepts only
/// packages the current workspace resolves. Profile dirs are found by
/// their `.fingerprint` dir (`target/debug`, `target/<triple>/release`,
/// ...); outputs are named `<package>-<hash>` there and in `build/`, and
/// `<crate>-<hash>` / `lib<crate>-<hash>` in `deps/` and `incremental/`
/// (crate = package with `-` as `_`). Returns the names removed.
pub fn clean_stale(
    target: &Path,
    current: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    let norm = |n: &str| n.replace('-', "_");
    let keep: std::collections::BTreeSet<String> = current.iter().map(|n| norm(n)).collect();
    let mut profiles = Vec::new();
    let mut stack = vec![(target.to_owned(), 0u8)];
    while let Some((d, depth)) = stack.pop() {
        if d.join(".fingerprint").is_dir() {
            profiles.push(d.clone());
        }
        if depth < 2 {
            for e in fs::read_dir(&d).into_iter().flatten().flatten() {
                let p = e.path();
                if e.file_type().is_ok_and(|t| t.is_dir())
                    && !e.file_name().to_string_lossy().starts_with('.')
                {
                    stack.push((p, depth + 1));
                }
            }
        }
    }
    // `<name>-<hash>` -> name: 16 hex digits, or 13 base-36 characters in
    // `incremental/`.
    let split = |file: &str| -> Option<String> {
        let (name, hash) = file.rsplit_once('-')?;
        ((13..=16).contains(&hash.len())
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()))
        .then(|| name.to_owned())
    };
    let mut removed = std::collections::BTreeSet::new();
    for prof in profiles {
        let mut stale = std::collections::BTreeSet::new();
        for e in fs::read_dir(prof.join(".fingerprint"))
            .into_iter()
            .flatten()
            .flatten()
        {
            if let Some(name) = split(&e.file_name().to_string_lossy())
                && !keep.contains(&norm(&name))
            {
                stale.insert(norm(&name));
            }
        }
        if stale.is_empty() {
            continue;
        }
        for sub in [".fingerprint", "build", "deps", "incremental"] {
            for e in fs::read_dir(prof.join(sub)).into_iter().flatten().flatten() {
                let file = e.file_name().to_string_lossy().into_owned();
                let stem = file.split('.').next().unwrap_or("");
                // `libfoo-<hash>.rlib` is crate foo, but a package may be
                // named `libfoo` too: stale only when no reading is kept.
                let names: Vec<String> = [Some(stem), stem.strip_prefix("lib")]
                    .into_iter()
                    .flatten()
                    .filter_map(split)
                    .map(|n| norm(&n))
                    .collect();
                if let Some(name) = names.iter().find(|n| stale.contains(*n)).cloned()
                    && !names.iter().any(|n| keep.contains(n))
                {
                    let p = e.path();
                    let gone = if p.is_dir() {
                        fs::remove_dir_all(&p)
                    } else {
                        fs::remove_file(&p)
                    };
                    if gone.is_ok() {
                        removed.insert(name);
                    }
                }
            }
        }
    }
    removed
}

/// Total size of the files under `dir` (symlinks not followed).
#[must_use]
pub fn dir_size(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_owned()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(md) = e.path().symlink_metadata() else {
                continue;
            };
            if md.is_dir() {
                stack.push(e.path());
            } else {
                total = total.saturating_add(md.len());
            }
        }
    }
    total
}
