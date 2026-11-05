//! The job environment (R52, D6).
//!
//! Every setup step, step and verify-checkout git call starts from
//! `env_clear()` and gets only this allowlist:
//!
//! - `PATH`: `job.path_prepend`, then `$CARGO_HOME/bin` (default
//!   `~/.cargo/bin`), `~/.local/bin`, `~/.bun/bin`, `/usr/local/bin`,
//!   `/usr/bin`, `/bin`
//! - `HOME`, and `USER`, `LOGNAME`, `SHELL`, `CARGO_HOME`, `RUSTUP_HOME`,
//!   `DOCKER_HOST` when tollgate has them
//! - `LANG`/`LC_ALL` (`C.UTF-8`; `en_US.UTF-8` on macOS), `TERM=dumb`, `CI=1`
//! - `SSH_AUTH_SOCK` only with `job.allow_ssh_agent = true`
//! - host `[job.env]`, then the step's `env`, then its `env_file`
//! - `TOLLGATE=1`, `TMPDIR=<job dir>/tmp` (cannot be overridden)
//!
//! No `GIT_*` variable is ever passed, so the hook injection does not reach
//! test suites and repos that tests create are not gated. Inherited values
//! (`GIT_INDEX_FILE`, `GUARD_EVAL_ONLY`, ...) cannot make a pass depend on one
//! agent's shell.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::check_env_key;
use crate::config::host::JobConfig;
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;

/// Variables copied from tollgate's own environment when present.
const PASS_THROUGH: &[&str] = &[
    "USER",
    "LOGNAME",
    "SHELL",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "DOCKER_HOST",
];

#[cfg(target_os = "macos")]
const LOCALE: &str = "en_US.UTF-8";
#[cfg(not(target_os = "macos"))]
const LOCALE: &str = "C.UTF-8";

/// Error while building a job environment.
#[derive(Debug, thiserror::Error)]
pub enum JobEnvError {
    /// A config source names a variable the runner owns or forbids.
    #[error("{source_name}: {message}")]
    Forbidden {
        /// `job.env`, `step env`, or the env file path.
        source_name: String,
        /// Why.
        message: String,
    },
    /// An env file cannot be read or parsed.
    #[error("env_file {path}: {message}")]
    EnvFile {
        /// File.
        path: PathBuf,
        /// Why.
        message: String,
    },
}

/// What the base job environment is built from.
#[derive(Debug, Clone, Copy)]
pub struct BaseInputs<'a> {
    /// tollgate's own environment (hook or CLI).
    pub env: &'a EnvSnapshot,
    /// For `HOME` and `~` expansion.
    pub dirs: &'a Dirs,
    /// Host `[job]`.
    pub job: &'a JobConfig,
    /// `<job dir>/tmp`.
    pub tmpdir: &'a Path,
}

/// A step's `env_file`, read once: its variables and the hash for the
/// fingerprint (R74).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvFile {
    /// File.
    pub path: PathBuf,
    /// Parsed variables.
    pub vars: BTreeMap<String, String>,
    /// blake3 of the file bytes.
    pub hash: String,
}

impl EnvFile {
    /// Reads and parses `path`.
    pub fn read(path: &Path) -> Result<Self, JobEnvError> {
        let bytes = std::fs::read(path).map_err(|e| JobEnvError::EnvFile {
            path: path.to_owned(),
            message: e.to_string(),
        })?;
        let text = std::str::from_utf8(&bytes).map_err(|e| JobEnvError::EnvFile {
            path: path.to_owned(),
            message: format!("not UTF-8: {e}"),
        })?;
        let vars = parse_env_file(text).map_err(|message| JobEnvError::EnvFile {
            path: path.to_owned(),
            message,
        })?;
        Ok(Self {
            path: path.to_owned(),
            vars,
            hash: blake3::hash(&bytes).to_hex().to_string(),
        })
    }
}

/// Parses `KEY=VALUE` lines. Blank lines and `#` comments are skipped, an
/// `export ` prefix is allowed, and one pair of matching quotes around the
/// value is removed.
pub fn parse_env_file(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut vars = BTreeMap::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map_or(line, str::trim_start);
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {}: expected KEY=VALUE", n + 1))?;
        let key = key.trim();
        let value = value.trim();
        let value = match value.as_bytes() {
            [b'"', .., b'"'] if value.len() >= 2 => value[1..value.len() - 1]
                .replace("\\\"", "\"")
                .replace("\\\\", "\\"),
            [b'\'', .., b'\''] if value.len() >= 2 => value[1..value.len() - 1].to_owned(),
            _ => value.to_owned(),
        };
        vars.insert(key.to_owned(), value);
    }
    Ok(vars)
}

/// A built job environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobEnv {
    vars: BTreeMap<OsString, OsString>,
}

impl JobEnv {
    /// The environment shared by every step of a job (R52).
    pub fn base(inputs: &BaseInputs<'_>) -> Result<Self, JobEnvError> {
        let BaseInputs {
            env,
            dirs,
            job,
            tmpdir,
        } = *inputs;
        let home = dirs.home();
        let cargo_bin = env
            .get_nonempty("CARGO_HOME")
            .map_or_else(|| home.join(".cargo"), PathBuf::from)
            .join("bin");
        let mut path_dirs: Vec<PathBuf> = job
            .path_prepend
            .iter()
            .map(|p| dirs.expand_tilde(p))
            .collect();
        path_dirs.extend([
            cargo_bin,
            home.join(".local/bin"),
            home.join(".bun/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
        ]);
        let path = std::env::join_paths(&path_dirs).map_err(|e| JobEnvError::Forbidden {
            source_name: "job.path_prepend".into(),
            message: e.to_string(),
        })?;

        let mut vars = BTreeMap::new();
        vars.insert("PATH".into(), path);
        vars.insert("HOME".into(), home.as_os_str().to_owned());
        for key in PASS_THROUGH {
            if let Some(v) = env.get_nonempty(key) {
                vars.insert((*key).into(), v.to_owned());
            }
        }
        if job.allow_ssh_agent
            && let Some(v) = env.get_nonempty("SSH_AUTH_SOCK")
        {
            vars.insert("SSH_AUTH_SOCK".into(), v.to_owned());
        }
        vars.insert("LANG".into(), LOCALE.into());
        vars.insert("LC_ALL".into(), LOCALE.into());
        vars.insert("TERM".into(), "dumb".into());
        vars.insert("CI".into(), "1".into());
        let mut built = Self { vars };
        built.overlay("job.env", &job.env)?;
        built
            .vars
            .insert("TMPDIR".into(), tmpdir.as_os_str().to_owned());
        built.vars.insert("TOLLGATE".into(), "1".into());
        Ok(built)
    }

    /// The base environment plus a step's `env` and `env_file` (R52, R63).
    pub fn for_step(
        &self,
        step_env: &BTreeMap<String, String>,
        env_file: Option<&EnvFile>,
    ) -> Result<Self, JobEnvError> {
        let mut built = self.clone();
        built.overlay("step env", step_env)?;
        if let Some(f) = env_file {
            built.overlay(&f.path.display().to_string(), &f.vars)?;
        }
        Ok(built)
    }

    /// An environment from explicit variables, for tests and tool probes
    /// that need a different `PATH`. No allowlist is applied.
    #[must_use]
    pub fn from_vars<I, K, V>(vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            vars: vars
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    fn overlay(
        &mut self,
        source_name: &str,
        extra: &BTreeMap<String, String>,
    ) -> Result<(), JobEnvError> {
        for (k, v) in extra {
            check_env_key(k).map_err(|message| JobEnvError::Forbidden {
                source_name: source_name.to_owned(),
                message,
            })?;
            if v.contains('\0') {
                return Err(JobEnvError::Forbidden {
                    source_name: source_name.to_owned(),
                    message: format!("{k}: value contains NUL"),
                });
            }
            self.vars.insert(k.into(), v.into());
        }
        Ok(())
    }

    /// The value of `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&OsStr> {
        self.vars.get(OsStr::new(key)).map(OsString::as_os_str)
    }

    /// All variables in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.as_os_str(), v.as_os_str()))
    }

    /// Clears `cmd`'s environment and sets exactly these variables.
    pub fn apply<'c>(&self, cmd: &'c mut Command) -> &'c mut Command {
        cmd.env_clear().envs(&self.vars)
    }

    /// blake3 of the environment for the fingerprint (R74), without `TMPDIR`
    /// (per job) and with the `SSH_AUTH_SOCK` path reduced to "set" (the
    /// socket path changes every login and would void every record).
    #[must_use]
    pub fn fingerprint_hash(&self) -> String {
        let mut h = blake3::Hasher::new();
        for (k, v) in &self.vars {
            if k == "TMPDIR" {
                continue;
            }
            let v: &OsStr = if k == "SSH_AUTH_SOCK" {
                OsStr::new("set")
            } else {
                v
            };
            h.update(k.as_bytes());
            h.update(b"\0");
            h.update(v.as_bytes());
            h.update(b"\0");
        }
        h.finalize().to_hex().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        env: EnvSnapshot,
        dirs: Dirs,
        job: JobConfig,
    }

    fn fixture() -> Fixture {
        let env = EnvSnapshot::from_pairs([
            ("HOME", "/home/u"),
            ("USER", "u"),
            ("SHELL", "/bin/zsh"),
            ("PATH", "/agent/shims:/usr/bin"),
            ("GIT_DIR", "/agent/.git"),
            ("GIT_INDEX_FILE", "/agent/.git/index.lock"),
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", "/hooks"),
            ("GUARD_EVAL_ONLY", "1"),
            ("GATEHOUSE_DB", "x"),
            ("SSH_AUTH_SOCK", "/tmp/ssh-1/agent.1"),
            ("RUSTUP_HOME", "/home/u/.rustup"),
        ]);
        let dirs = Dirs::from_env(&env).unwrap();
        Fixture {
            env,
            dirs,
            job: JobConfig::default(),
        }
    }

    fn base(f: &Fixture, tmpdir: &str) -> JobEnv {
        JobEnv::base(&BaseInputs {
            env: &f.env,
            dirs: &f.dirs,
            job: &f.job,
            tmpdir: Path::new(tmpdir),
        })
        .unwrap()
    }

    fn keys(e: &JobEnv) -> Vec<String> {
        e.iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn allowlist_only_no_git_vars_r52() {
        let f = fixture();
        let e = base(&f, "/s/jobs/j/tmp");
        assert_eq!(
            keys(&e),
            [
                "CI",
                "HOME",
                "LANG",
                "LC_ALL",
                "PATH",
                "RUSTUP_HOME",
                "SHELL",
                "TERM",
                "TMPDIR",
                "TOLLGATE",
                "USER"
            ]
        );
        assert_eq!(e.get("TOLLGATE"), Some(OsStr::new("1")));
        assert_eq!(e.get("TMPDIR"), Some(OsStr::new("/s/jobs/j/tmp")));
        assert_eq!(
            e.get("PATH"),
            Some(OsStr::new(
                "/home/u/.cargo/bin:/home/u/.local/bin:/home/u/.bun/bin:/usr/local/bin:/usr/bin:/bin"
            ))
        );
    }

    #[test]
    fn path_prepend_cargo_home_and_ssh_agent() {
        let mut f = fixture();
        f.env.set("CARGO_HOME", "/opt/cargo");
        f.job.path_prepend = vec!["~/tools".into(), "/opt/x".into()];
        f.job.allow_ssh_agent = true;
        let e = base(&f, "/t");
        let path = e.get("PATH").unwrap().to_str().unwrap();
        assert!(
            path.starts_with("/home/u/tools:/opt/x:/opt/cargo/bin:"),
            "{path}"
        );
        assert_eq!(
            e.get("SSH_AUTH_SOCK"),
            Some(OsStr::new("/tmp/ssh-1/agent.1"))
        );
        assert_eq!(e.get("CARGO_HOME"), Some(OsStr::new("/opt/cargo")));
    }

    #[test]
    fn config_sources_overlay_in_order_and_reserved_keys_fail() {
        let mut f = fixture();
        f.job.env.insert("SQLX_OFFLINE".into(), "true".into());
        f.job.env.insert("LANG".into(), "de_DE.UTF-8".into());
        let e = base(&f, "/t");
        assert_eq!(e.get("SQLX_OFFLINE"), Some(OsStr::new("true")));
        assert_eq!(e.get("LANG"), Some(OsStr::new("de_DE.UTF-8")));

        let step: BTreeMap<String, String> =
            [("SQLX_OFFLINE".to_owned(), "false".to_owned())].into();
        let file = EnvFile {
            path: "/etc/x.env".into(),
            vars: [("TOKEN_FILE".to_owned(), "/k".to_owned())].into(),
            hash: String::new(),
        };
        let s = e.for_step(&step, Some(&file)).unwrap();
        assert_eq!(s.get("SQLX_OFFLINE"), Some(OsStr::new("false")));
        assert_eq!(s.get("TOKEN_FILE"), Some(OsStr::new("/k")));

        for bad in ["GIT_DIR", "GIT_CONFIG_COUNT", "TOLLGATE", "TMPDIR", "1X"] {
            let step: BTreeMap<String, String> = [(bad.to_owned(), "v".to_owned())].into();
            assert!(e.for_step(&step, None).is_err(), "{bad}");
        }
        f.job.env.insert("GIT_INDEX_FILE".into(), "x".into());
        assert!(
            JobEnv::base(&BaseInputs {
                env: &f.env,
                dirs: &f.dirs,
                job: &f.job,
                tmpdir: Path::new("/t"),
            })
            .is_err()
        );
    }

    #[test]
    fn fingerprint_hash_ignores_tmpdir_and_ssh_socket_path_r74() {
        let mut f = fixture();
        f.job.allow_ssh_agent = true;
        let a = base(&f, "/jobs/a/tmp");
        f.env.set("SSH_AUTH_SOCK", "/tmp/ssh-2/agent.9");
        let b = base(&f, "/jobs/b/tmp");
        assert_eq!(a.fingerprint_hash(), b.fingerprint_hash());
        f.job.env.insert("SQLX_OFFLINE".into(), "true".into());
        let c = base(&f, "/jobs/a/tmp");
        assert_ne!(a.fingerprint_hash(), c.fingerprint_hash());
        f.job.allow_ssh_agent = false;
        f.job.env.clear();
        let d = base(&f, "/jobs/a/tmp");
        assert_ne!(a.fingerprint_hash(), d.fingerprint_hash());
    }

    #[test]
    fn env_file_parsing() {
        let vars = parse_env_file(
            "# comment\n\nA=1\nexport B = two words \nC=\"q \\\"x\\\"\"\nD='s'\nE=\n",
        )
        .unwrap();
        assert_eq!(vars["A"], "1");
        assert_eq!(vars["B"], "two words");
        assert_eq!(vars["C"], "q \"x\"");
        assert_eq!(vars["D"], "s");
        assert_eq!(vars["E"], "");
        assert!(parse_env_file("novalue\n").unwrap_err().contains("line 1"));
    }

    #[test]
    fn env_file_read_hashes_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x.env");
        std::fs::write(&p, "A=1\n").unwrap();
        let a = EnvFile::read(&p).unwrap();
        std::fs::write(&p, "A=2\n").unwrap();
        let b = EnvFile::read(&p).unwrap();
        assert_ne!(a.hash, b.hash);
        assert!(EnvFile::read(&tmp.path().join("missing")).is_err());
    }
}
