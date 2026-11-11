//! The `git` wrapper (D3, R12, R52).
//!
//! tollgate shells out to the `git` binary: the same semantics as the git
//! that runs the hook. Every call:
//!
//! - sets `GIT_NO_REPLACE_OBJECTS=1`, so a replace ref cannot make tollgate
//!   check another tree than the one pushed (R12, L1 keeps this);
//! - has stdin closed, so it cannot eat a hook's stdin (pre-push ref lines);
//! - runs in an explicit directory (`-C`).
//!
//! Two environments:
//!
//! - [`Git::scrubbed`] (hook and CLI calls): tollgate's environment without
//!   any `GIT_*` variable except an allowlist (config file locations, ssh,
//!   identity, trace). `GIT_DIR`, `GIT_INDEX_FILE`, `GIT_WORK_TREE`,
//!   `GIT_PREFIX`, the `GIT_CONFIG_COUNT`/`KEY`/`VALUE` injection and
//!   `GIT_CONFIG_PARAMETERS` are removed (R52). [`Git::with_index_file`]
//!   names the hook's own index explicitly (R17). `GIT_OPTIONAL_LOCKS=0`
//!   keeps read-only calls from writing the agent's index.
//! - [`Git::for_checkout`] (verify checkout): the job environment (R52) plus
//!   explicit `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE`, and
//!   [`CHECKOUT_CONFIG`] as command-line config: the checkout shares the
//!   agent's repo config, and no value there may change what the checkout
//!   holds or run a program in it (review note 14).
//!
//! Item 39: the binary is [`program`], an absolute path fixed at install
//! (`install.json`), never `git` looked up on `PATH`: git puts
//! `GIT_EXEC_PATH` first on its hooks' `PATH`, so a `git` there would answer
//! tollgate's own calls. `GIT_EXEC_PATH` is removed from every git tollgate
//! starts.

pub mod config_file;
pub mod hooks_path;
pub mod layout;
pub mod lockfiles;
pub mod ref_files;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::{Deserialize, Serialize};

use crate::env::EnvSnapshot;
use crate::runner::env::JobEnv;

/// Config every git call in a verify checkout runs with (review note 14):
/// no fsmonitor or hook program runs there; line endings, symlinks, modes
/// and sparse checkout are git's defaults, never the repo config's; and
/// no attributes file outside the tree is read (`info/attributes` is
/// checked by [`crate::runner::checkout`]). Filter drivers have free names,
/// so they cannot be pinned: the checkout proves the content of each
/// filtered path instead.
pub const CHECKOUT_CONFIG: &[(&str, &str)] = &[
    ("core.fsmonitor", "false"),
    ("core.hooksPath", "/dev/null"),
    ("core.autocrlf", "false"),
    ("core.eol", "lf"),
    ("core.symlinks", "true"),
    ("core.fileMode", "true"),
    ("core.sparseCheckout", "false"),
    ("index.sparse", "false"),
    ("core.attributesFile", "/dev/null"),
];

pub use layout::RepoLayout;

/// Dirs searched for git when no install records one (item 39); the same
/// system dirs as the trusted-server query's `PATH` (X1).
#[cfg(not(target_os = "macos"))]
pub const SYSTEM_GIT_DIRS: &[&str] = &["/usr/local/bin", "/usr/bin", "/bin"];

/// Dirs searched for git when no install records one (item 39): the
/// trusted-server query's system dirs (X1) with the Command Line Tools
/// before `/usr/bin`. On macOS `/usr/bin/git` is the `xcrun` shim: each
/// call first runs `xcrun` to find the developer dir (measured
/// 2026-11-11, CPU time per `git rev-parse`: shim 9.7-13.1 ms, Command
/// Line Tools git 7.1 ms, Xcode git 4.4 ms). Xcode's git is not searched: `/Applications`
/// is writable by the admin group, and a bundle copied in by hand belongs
/// to its user. A git here counts only when [`root_controlled`].
#[cfg(target_os = "macos")]
pub const SYSTEM_GIT_DIRS: &[&str] = &[
    "/usr/local/bin",
    "/Library/Developer/CommandLineTools/usr/bin",
    "/usr/bin",
    "/bin",
];

static PROGRAM: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// The first executable `git` in `prepend`, then [`SYSTEM_GIT_DIRS`]: never
/// the caller's `PATH` (item 39).
#[must_use]
pub fn find_git(prepend: &[PathBuf]) -> Option<PathBuf> {
    find_git_in(prepend, SYSTEM_GIT_DIRS)
}

/// [`find_git`] with `system` as the system dirs. On macOS a git in a
/// system dir counts only when [`root_controlled`]: `/usr/local/bin` can
/// belong to a user there (Homebrew on Intel), so a git a session wrote
/// in it would answer before the system's.
fn find_git_in(prepend: &[PathBuf], system: &[&str]) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;
    let executable = |p: &Path| {
        p.is_absolute()
            && std::fs::metadata(p)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    };
    prepend
        .iter()
        .map(|d| d.join("git"))
        .find(|p| executable(p))
        .or_else(|| {
            system
                .iter()
                .map(|d| Path::new(d).join("git"))
                .find(|p| executable(p) && (cfg!(not(target_os = "macos")) || root_controlled(p)))
        })
}

/// True when `path` (followed through symlinks) and every dir above it
/// up to `/` belong to root and no group or other can write them: no
/// user can put another program there.
fn root_controlled(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    let Ok(real) = path.canonicalize() else {
        return false;
    };
    real.ancestors()
        .all(|p| std::fs::metadata(p).is_ok_and(|m| m.uid() == 0 && m.mode() & 0o022 == 0))
}

/// The git `install.json` records for the install that `exe` belongs to
/// (`<data dir>/bin/tollgate` or `<data dir>/hooks/<name>`), else for the
/// install of `env`'s dirs.
fn recorded_git(exe: &Path, env: &EnvSnapshot) -> Option<PathBuf> {
    let beside = exe
        .parent()
        .and_then(Path::parent)
        .map(|d| d.join("install.json"));
    let record = beside.filter(|p| p.is_file()).or_else(|| {
        crate::dirs::Dirs::from_env(env)
            .ok()
            .map(|d| d.install_record())
    })?;
    crate::install::InstallRecord::read_at(&record).ok()?.git
}

/// Fixes the git of this process (item 39): the one `install.json`
/// records for `exe`'s install (or `env`'s), else [`find_git`]. Call it
/// before the first git call; later calls change nothing.
pub fn init_program(exe: &Path, env: &EnvSnapshot) {
    let _ = PROGRAM.set(
        recorded_git(exe, env)
            .or_else(|| find_git(&[]))
            .unwrap_or_else(|| PathBuf::from("git")),
    );
}

/// The git binary every tollgate git call runs (item 39): set by
/// [`init_program`]; without it (library tests), [`find_git`].
#[must_use]
pub fn program() -> &'static Path {
    PROGRAM.get_or_init(|| find_git(&[]).unwrap_or_else(|| PathBuf::from("git")))
}

/// `GIT_*` variables a scrubbed call keeps from tollgate's environment.
/// Never `GIT_EXEC_PATH` (item 39).
const GIT_PASS_THROUGH: &[&str] = &[
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
    "GIT_ASKPASS",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
];

/// True when a scrubbed call keeps `key`.
fn keep_git_var(key: &str) -> bool {
    GIT_PASS_THROUGH.contains(&key) || key.starts_with("GIT_TRACE")
}

/// Error from a git call.
#[derive(Debug, thiserror::Error)]
pub enum GitError {
    /// `git` could not be started.
    #[error("cannot run git: {0}")]
    Spawn(#[source] std::io::Error),
    /// `git` exited non-zero.
    #[error("git {args} failed ({status}): {stderr}")]
    Failed {
        /// Arguments.
        args: String,
        /// Exit status.
        status: String,
        /// Trimmed stderr.
        stderr: String,
    },
    /// The output was not what tollgate expects.
    #[error("git {args}: unexpected output: {detail}")]
    Output {
        /// Arguments.
        args: String,
        /// What was wrong.
        detail: String,
    },
}

/// A git object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Oid(String);

impl Oid {
    /// Parses an object id.
    pub fn parse(value: &str) -> Result<Self, String> {
        let ok = (value.len() == 40 || value.len() == 64)
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if ok {
            Ok(Self(value.to_owned()))
        } else {
            Err(format!("invalid object id {value:?}"))
        }
    }

    /// The hex text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for the all-zero id.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0.bytes().all(|b| b == b'0')
    }

    /// The first `n` characters, for reports (`T[..12]`, R91).
    #[must_use]
    pub fn short(&self, n: usize) -> &str {
        &self.0[..n.min(self.0.len())]
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Oid {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<Oid> for String {
    fn from(value: Oid) -> Self {
        value.0
    }
}

/// The repository hash algorithm (`git rev-parse --show-object-format`, R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    /// 40 hex characters.
    Sha1,
    /// 64 hex characters.
    Sha256,
}

impl ObjectFormat {
    /// Hex length of an id.
    #[must_use]
    pub fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }

    /// The zero id.
    #[must_use]
    pub fn zero(self) -> Oid {
        Oid("0".repeat(self.hex_len()))
    }

    /// The empty tree (R17: base of an unborn branch).
    #[must_use]
    pub fn empty_tree(self) -> Oid {
        Oid(match self {
            Self::Sha1 => "4b825dc642cb6eb9a060e54bf8d69288fbee4904".into(),
            Self::Sha256 => {
                "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321".into()
            }
        })
    }
}

/// One entry of `git ls-tree -r` (L16 step inputs, R45 setup `when`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    /// Mode, e.g. `100644`, `100755`, `120000`, `160000`.
    pub mode: String,
    /// Object type: `blob` or `commit` (submodule).
    pub kind: String,
    /// Object id.
    pub oid: Oid,
    /// Repo-relative path, bytes as stored.
    pub path: PathBuf,
}

/// A prepared git invocation context.
#[derive(Debug, Clone)]
pub struct Git {
    program: OsString,
    dir: PathBuf,
    env: BTreeMap<OsString, OsString>,
}

impl Git {
    /// Git for hook and CLI calls in `dir`, with a scrubbed copy of `env`.
    #[must_use]
    pub fn scrubbed(env: &EnvSnapshot, dir: impl Into<PathBuf>) -> Self {
        let mut vars: BTreeMap<OsString, OsString> = env
            .iter()
            .filter(|(k, _)| {
                k.to_str()
                    .is_some_and(|k| !k.starts_with("GIT_") || keep_git_var(k))
            })
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        vars.insert("GIT_OPTIONAL_LOCKS".into(), "0".into());
        vars.insert("LC_ALL".into(), "C".into());
        Self::with_env(vars, dir.into())
    }

    /// Git for a verify checkout: the job environment plus explicit
    /// `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` (R52), with
    /// [`CHECKOUT_CONFIG`] pinned and `GIT_ATTR_NOSYSTEM=1` (R42, review
    /// note 14).
    #[must_use]
    pub fn for_checkout(
        job_env: &JobEnv,
        worktree: &Path,
        git_dir: &Path,
        index_file: &Path,
    ) -> Self {
        let mut vars: BTreeMap<OsString, OsString> = job_env
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        vars.insert("GIT_DIR".into(), git_dir.as_os_str().to_owned());
        vars.insert("GIT_WORK_TREE".into(), worktree.as_os_str().to_owned());
        vars.insert("GIT_INDEX_FILE".into(), index_file.as_os_str().to_owned());
        // Review note 14: the checkout shares the agent's repo config.
        // Command-line config outranks every config file, so none of these
        // can come from there; the system attributes file is not read.
        vars.insert("GIT_ATTR_NOSYSTEM".into(), "1".into());
        vars.insert(
            "GIT_CONFIG_COUNT".into(),
            CHECKOUT_CONFIG.len().to_string().into(),
        );
        for (i, (k, v)) in CHECKOUT_CONFIG.iter().enumerate() {
            vars.insert(format!("GIT_CONFIG_KEY_{i}").into(), (*k).into());
            vars.insert(format!("GIT_CONFIG_VALUE_{i}").into(), (*v).into());
        }
        Self::with_env(vars, worktree.to_owned())
    }

    fn with_env(mut vars: BTreeMap<OsString, OsString>, dir: PathBuf) -> Self {
        vars.insert("GIT_NO_REPLACE_OBJECTS".into(), "1".into());
        vars.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        vars.remove(OsStr::new("GIT_EXEC_PATH"));
        Self {
            program: program().as_os_str().to_owned(),
            dir,
            env: vars,
        }
    }

    /// The same context with `GIT_INDEX_FILE` set to the hook's index (R17).
    #[must_use]
    pub fn with_index_file(mut self, index_file: &Path) -> Self {
        self.env
            .insert("GIT_INDEX_FILE".into(), index_file.as_os_str().to_owned());
        self
    }

    /// The same context in another directory.
    #[must_use]
    pub fn in_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.dir = dir.into();
        self
    }

    /// The directory passed with `-C`.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// A variable of the call environment.
    #[must_use]
    pub fn env_var(&self, key: &str) -> Option<&OsStr> {
        self.env.get(OsStr::new(key)).map(OsString::as_os_str)
    }

    /// A ready [`Command`] for `args`, with stdin closed.
    pub fn command<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut cmd = Command::new(&self.program);
        cmd.env_clear()
            .envs(&self.env)
            .arg("-C")
            .arg(&self.dir)
            .args(args)
            .stdin(Stdio::null());
        cmd
    }

    /// Runs `args` and returns the output whatever the exit status.
    pub fn output<I, S>(&self, args: I) -> Result<Output, GitError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.command(args).output().map_err(GitError::Spawn)
    }

    /// Runs `args` with `input` on stdin; non-zero exit is an error.
    /// Returns stdout. stdin is written from another thread, so a large
    /// output never blocks the write.
    pub fn run_with_input<I, S>(&self, args: I, input: &[u8]) -> Result<Vec<u8>, GitError>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        use std::io::Write as _;
        let mut child = self
            .command(args.clone())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(GitError::Spawn)?;
        let mut stdin = child.stdin.take();
        let out = std::thread::scope(|s| {
            s.spawn(move || {
                if let Some(w) = stdin.as_mut() {
                    // A write error means git exited early; its status says why.
                    let _ = w.write_all(input);
                }
                drop(stdin);
            });
            child.wait_with_output()
        })
        .map_err(GitError::Spawn)?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(failed(args, &out))
        }
    }

    /// Runs `args`; non-zero exit is an error. Returns stdout.
    pub fn run<I, S>(&self, args: I) -> Result<Vec<u8>, GitError>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let out = self.output(args.clone())?;
        if out.status.success() {
            Ok(out.stdout)
        } else {
            Err(failed(args, &out))
        }
    }

    /// Runs `args` and returns stdout as one trimmed UTF-8 line.
    pub fn run_line<I, S>(&self, args: I) -> Result<String, GitError>
    where
        I: IntoIterator<Item = S> + Clone,
        S: AsRef<OsStr>,
    {
        let stdout = self.run(args.clone())?;
        String::from_utf8(stdout)
            .map(|s| s.trim_end_matches(['\n', '\r']).to_owned())
            .map_err(|e| GitError::Output {
                args: join_args(args),
                detail: e.to_string(),
            })
    }

    /// `rev-parse --verify --quiet <rev>`: `None` when it does not resolve.
    pub fn rev_parse_verify(&self, rev: &str) -> Result<Option<Oid>, GitError> {
        let args = ["rev-parse", "--verify", "--quiet", "--end-of-options", rev];
        let out = self.output(args)?;
        match out.status.code() {
            Some(0) => parse_oid_output(&args, &out.stdout).map(Some),
            Some(1) => Ok(None),
            _ => Err(failed(args, &out)),
        }
    }

    /// The tree of `rev` (`<rev>^{tree}`), `None` when it does not resolve.
    pub fn tree_of(&self, rev: &str) -> Result<Option<Oid>, GitError> {
        self.rev_parse_verify(&format!("{rev}^{{tree}}"))
    }

    /// `git write-tree` of the current index (R17).
    pub fn write_tree(&self) -> Result<Oid, GitError> {
        let args = ["write-tree"];
        let out = self.run(args)?;
        parse_oid_output(&args, &out)
    }

    /// Every entry of `tree`, recursively (`git ls-tree -r -z --full-tree`).
    pub fn ls_tree(&self, tree: &Oid) -> Result<Vec<TreeEntry>, GitError> {
        let args = ["ls-tree", "-r", "-z", "--full-tree", tree.as_str()];
        let out = self.run(args)?;
        let bad = |detail: String| GitError::Output {
            args: join_args(args),
            detail,
        };
        let mut entries = Vec::new();
        for rec in out.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let tab = rec
                .iter()
                .position(|b| *b == b'\t')
                .ok_or_else(|| bad("entry without a tab".into()))?;
            let head = std::str::from_utf8(&rec[..tab]).map_err(|e| bad(e.to_string()))?;
            let mut parts = head.split(' ');
            let (Some(mode), Some(kind), Some(oid), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                return Err(bad(format!("bad entry {head:?}")));
            };
            entries.push(TreeEntry {
                mode: mode.to_owned(),
                kind: kind.to_owned(),
                oid: Oid::parse(oid).map_err(bad)?,
                path: PathBuf::from(std::ffi::OsStr::from_bytes(&rec[tab + 1..])),
            });
        }
        Ok(entries)
    }

    /// `rev-parse --show-object-format` (R10).
    pub fn object_format(&self) -> Result<ObjectFormat, GitError> {
        let args = ["rev-parse", "--show-object-format"];
        match self.run_line(args)?.as_str() {
            "sha1" => Ok(ObjectFormat::Sha1),
            "sha256" => Ok(ObjectFormat::Sha256),
            other => Err(GitError::Output {
                args: join_args(args),
                detail: format!("unknown object format {other:?}"),
            }),
        }
    }

    /// The compiled-in system config path (`git var GIT_CONFIG_SYSTEM`, needs
    /// git 2.42 or later), ignoring `GIT_CONFIG_SYSTEM` and `GIT_CONFIG_NOSYSTEM`.
    /// R7 applies those variables itself; callers cache the result per git
    /// binary.
    pub fn system_config_default(&self) -> Result<Option<PathBuf>, GitError> {
        let mut git = self.clone();
        git.env.remove(OsStr::new("GIT_CONFIG_SYSTEM"));
        git.env.remove(OsStr::new("GIT_CONFIG_NOSYSTEM"));
        let args = ["var", "GIT_CONFIG_SYSTEM"];
        let out = git.output(args)?;
        if !out.status.success() {
            return Err(failed(args, &out));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        Ok(text
            .lines()
            .next()
            .filter(|l| !l.is_empty())
            .map(PathBuf::from))
    }
}

fn join_args<I, S>(args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    args.into_iter()
        .map(|a| a.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

fn failed<I, S>(args: I, out: &Output) -> GitError
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    GitError::Failed {
        args: join_args(args),
        status: out.status.to_string(),
        stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
    }
}

fn parse_oid_output<S: AsRef<OsStr>>(args: &[S], stdout: &[u8]) -> Result<Oid, GitError> {
    let text = String::from_utf8_lossy(stdout);
    Oid::parse(text.trim()).map_err(|detail| GitError::Output {
        args: join_args(args),
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An executable `git` in a new dir of this (non-root) user.
    fn user_git() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let git = dir.path().join("git");
        std::fs::write(&git, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&git, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        (dir, git)
    }

    /// macOS: the Command Line Tools' git wins over the `/usr/bin/git`
    /// shim; Xcode's is never searched; `[job] path_prepend` still comes
    /// first, whoever owns it.
    #[cfg(target_os = "macos")]
    #[test]
    fn find_git_skips_the_xcrun_shim_on_macos() {
        assert!(
            !SYSTEM_GIT_DIRS
                .iter()
                .any(|d| d.starts_with("/Applications"))
        );
        let found = find_git(&[]).expect("a git");
        let local = Path::new("/usr/local/bin/git");
        let clt = Path::new("/Library/Developer/CommandLineTools/usr/bin/git");
        if local.is_file() && root_controlled(local) {
            assert_eq!(found, local);
        } else if clt.is_file() {
            assert_eq!(found, clt);
        } else {
            assert_eq!(found, Path::new("/usr/bin/git"));
        }
        let (dir, mine) = user_git();
        assert_eq!(find_git(&[dir.path().to_owned()]), Some(mine));
    }

    /// macOS: a git in a system dir that a user owns or can write (a
    /// user-owned `/usr/local/bin`, an `/Applications` bundle) is skipped.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_user_writable_system_git_is_never_picked_on_macos() {
        let (dir, mine) = user_git();
        let user_dir = dir.path().to_str().unwrap();
        assert!(!root_controlled(&mine));
        assert_eq!(
            find_git_in(&[], &[user_dir, "/usr/bin"]),
            Some(PathBuf::from("/usr/bin/git"))
        );
        assert!(root_controlled(Path::new("/usr/bin/git")));
        // `/Applications` is group-writable (root:admin 0775).
        assert!(!root_controlled(Path::new("/Applications")));
    }

    /// Linux keeps the first executable git, as before.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn find_git_takes_the_first_system_git_on_linux() {
        let (dir, mine) = user_git();
        let user_dir = dir.path().to_str().unwrap();
        assert_eq!(find_git_in(&[], &[user_dir, "/usr/bin"]), Some(mine));
    }

    #[test]
    fn oid_validation() {
        assert!(Oid::parse(&"a".repeat(40)).is_ok());
        assert!(Oid::parse(&"0".repeat(64)).unwrap().is_zero());
        assert!(Oid::parse(&"a".repeat(41)).is_err());
        assert!(Oid::parse(&"A".repeat(40)).is_err());
        assert_eq!(ObjectFormat::Sha256.zero().as_str().len(), 64);
    }

    #[test]
    fn scrubbed_env_drops_index_dir_and_injection_r52() {
        let env = EnvSnapshot::from_pairs([
            ("PATH", "/usr/bin"),
            ("HOME", "/h"),
            ("GIT_DIR", "/a/.git"),
            ("GIT_INDEX_FILE", "/a/.git/index.lock"),
            ("GIT_WORK_TREE", "/a"),
            ("GIT_PREFIX", "sub/"),
            ("GIT_COMMON_DIR", "/a/.git"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", "/hooks"),
            ("GIT_CONFIG_PARAMETERS", "'core.hookspath'='/x'"),
            ("GIT_CONFIG_GLOBAL", "/g"),
            ("GIT_TRACE2_EVENT", "/t"),
            ("GIT_OBJECT_DIRECTORY", "/elsewhere"),
        ]);
        let g = Git::scrubbed(&env, "/repo");
        for gone in [
            "GIT_DIR",
            "GIT_INDEX_FILE",
            "GIT_WORK_TREE",
            "GIT_PREFIX",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_COUNT",
            "GIT_CONFIG_KEY_0",
            "GIT_CONFIG_VALUE_0",
            "GIT_CONFIG_PARAMETERS",
            "GIT_OBJECT_DIRECTORY",
        ] {
            assert_eq!(g.env_var(gone), None, "{gone}");
        }
        assert_eq!(g.env_var("GIT_CONFIG_GLOBAL"), Some(OsStr::new("/g")));
        assert_eq!(g.env_var("GIT_TRACE2_EVENT"), Some(OsStr::new("/t")));
        assert_eq!(g.env_var("GIT_NO_REPLACE_OBJECTS"), Some(OsStr::new("1")));
        assert_eq!(g.env_var("GIT_OPTIONAL_LOCKS"), Some(OsStr::new("0")));
        assert_eq!(g.env_var("PATH"), Some(OsStr::new("/usr/bin")));
        let with = g.with_index_file(Path::new("/a/.git/next-index-1.lock"));
        assert_eq!(
            with.env_var("GIT_INDEX_FILE"),
            Some(OsStr::new("/a/.git/next-index-1.lock"))
        );
    }

    #[test]
    fn checkout_env_is_the_job_env_plus_explicit_dirs_r52() {
        let job = JobEnv::from_vars([("PATH", "/usr/bin"), ("HOME", "/h")]);
        let g = Git::for_checkout(
            &job,
            Path::new("/v/wt"),
            Path::new("/r/.git/worktrees/wt"),
            Path::new("/r/.git/worktrees/wt/index"),
        );
        assert_eq!(
            g.env_var("GIT_DIR"),
            Some(OsStr::new("/r/.git/worktrees/wt"))
        );
        assert_eq!(g.env_var("GIT_WORK_TREE"), Some(OsStr::new("/v/wt")));
        assert_eq!(
            g.env_var("GIT_INDEX_FILE"),
            Some(OsStr::new("/r/.git/worktrees/wt/index"))
        );
        assert_eq!(g.env_var("GIT_NO_REPLACE_OBJECTS"), Some(OsStr::new("1")));
        assert_eq!(g.dir(), Path::new("/v/wt"));
        // Review note 14: the pinned config, as command-line config.
        assert_eq!(g.env_var("GIT_ATTR_NOSYSTEM"), Some(OsStr::new("1")));
        let n: usize = g
            .env_var("GIT_CONFIG_COUNT")
            .and_then(OsStr::to_str)
            .unwrap()
            .parse()
            .unwrap();
        let pinned: Vec<(String, String)> = (0..n)
            .map(|i| {
                let get = |k: String| g.env_var(&k).unwrap().to_string_lossy().into_owned();
                (
                    get(format!("GIT_CONFIG_KEY_{i}")),
                    get(format!("GIT_CONFIG_VALUE_{i}")),
                )
            })
            .collect();
        for key in ["core.fsmonitor", "core.hooksPath", "core.attributesFile"] {
            assert!(pinned.iter().any(|(k, _)| k == key), "{key}: {pinned:?}");
        }
        assert_eq!(pinned.len(), CHECKOUT_CONFIG.len());
    }
}
