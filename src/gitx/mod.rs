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
//!   explicit `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE`.

pub mod config_file;
pub mod hooks_path;
pub mod layout;
pub mod lockfiles;

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde::{Deserialize, Serialize};

use crate::env::EnvSnapshot;
use crate::runner::env::JobEnv;

pub use layout::RepoLayout;

/// `GIT_*` variables a scrubbed call keeps from tollgate's environment.
const GIT_PASS_THROUGH: &[&str] = &[
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CEILING_DIRECTORIES",
    "GIT_EXEC_PATH",
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
    /// `GIT_DIR`, `GIT_WORK_TREE` and `GIT_INDEX_FILE` (R52).
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
        Self::with_env(vars, worktree.to_owned())
    }

    fn with_env(mut vars: BTreeMap<OsString, OsString>, dir: PathBuf) -> Self {
        vars.insert("GIT_NO_REPLACE_OBJECTS".into(), "1".into());
        vars.insert("GIT_TERMINAL_PROMPT".into(), "0".into());
        Self {
            program: "git".into(),
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
    }
}
