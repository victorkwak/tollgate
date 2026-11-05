//! Shared helpers for integration tests: a sandbox HOME and real git repos.
//!
//! Every test points HOME, XDG dirs and git's global config into a temp
//! dir, so nothing reads or writes the real ~/.config, ~/.local or ~/.claude.

// Each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tollgate::env::EnvSnapshot;

/// A temp dir with a sandbox HOME.
pub struct Sandbox {
    pub tmp: tempfile::TempDir,
    pub home: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n",
        )
        .unwrap();
        Self { tmp, home }
    }

    /// The sandbox root (canonical).
    pub fn root(&self) -> PathBuf {
        self.home.parent().unwrap().to_owned()
    }

    /// Environment for tollgate code and git in the sandbox.
    pub fn env(&self) -> EnvSnapshot {
        let root = self.root();
        EnvSnapshot::from_pairs([
            ("PATH", std::env::var_os("PATH").unwrap_or_default()),
            ("HOME", self.home.clone().into_os_string()),
            ("XDG_STATE_HOME", root.join("state").into_os_string()),
            ("XDG_DATA_HOME", root.join("data").into_os_string()),
            ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
            ("GIT_CONFIG_NOSYSTEM", "1".into()),
            ("LANG", "C".into()),
        ])
    }

    /// Runs real git in `dir` with the sandbox env plus `extra`.
    pub fn git_output(&self, dir: &Path, args: &[&str], extra: &[(&str, &OsStr)]) -> Output {
        let mut cmd = Command::new("git");
        cmd.env_clear();
        for (k, v) in self.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.current_dir(dir).args(args).output().unwrap()
    }

    /// Runs real git; panics on failure; returns trimmed stdout.
    pub fn git(&self, dir: &Path, args: &[&str]) -> String {
        self.git_with(dir, args, &[])
    }

    pub fn git_with(&self, dir: &Path, args: &[&str], extra: &[(&str, &OsStr)]) -> String {
        let out = self.git_output(dir, args, extra);
        assert!(
            out.status.success(),
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// A new repo under the sandbox root with one commit.
    pub fn repo(&self, name: &str) -> PathBuf {
        let dir = self.root().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q"]);
        self.commit_file(&dir, "README", "hello\n", "init");
        dir
    }

    /// Writes `path`, stages it, commits; returns the commit id.
    pub fn commit_file(&self, repo: &Path, path: &str, content: &str, msg: &str) -> String {
        let file = repo.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, content).unwrap();
        self.git(repo, &["add", path]);
        self.git(repo, &["commit", "-q", "--no-verify", "-m", msg]);
        self.git(repo, &["rev-parse", "HEAD"])
    }
}

/// Canonicalizes the longest existing prefix of `p` (paths that may not
/// exist yet still compare equal across symlinked temp dirs).
pub fn norm(p: &Path) -> PathBuf {
    let mut existing = p.to_owned();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_owned());
                existing = parent.to_owned();
            }
            _ => break,
        }
    }
    let mut out = existing.canonicalize().unwrap_or(existing);
    for part in rest.iter().rev() {
        out.push(part);
    }
    out
}
