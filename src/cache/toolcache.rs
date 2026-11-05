//! Tool version cache (R75): `$XDG_STATE_HOME/tollgate/toolcache.json`.
//!
//! A version string is stored with the identity of the binary that printed
//! it: realpath, size, mtime, device and inode. A lookup whose identity
//! still matches runs no subprocess.
//!
//! rustup proxies (`~/.cargo/bin/rustc` -> `rustup`) do not change when
//! `rustup update` installs a new toolchain, so their identity also carries a
//! context hash of what picks the toolchain: `RUSTUP_TOOLCHAIN`,
//! `$RUSTUP_HOME/settings.toml` (default and path overrides), the nearest
//! `rust-toolchain(.toml)` above the working dir, and the stat of
//! `toolchains/*/bin/<tool>`. No subprocess is needed for that either.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::fsx;
use crate::runner::env::JobEnv;

const FILE_VERSION: u32 = 1;

/// A version probe: run `program args` and keep its output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// Fingerprint key and cache id.
    pub id: &'static str,
    /// Program looked up on the job `PATH`.
    pub program: &'static str,
    /// Arguments.
    pub args: &'static [&'static str],
}

/// What a probe found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Not on the job `PATH`.
    Absent,
    /// The trimmed output.
    Version(String),
}

impl ProbeResult {
    /// The fingerprint value: the output, or `absent`.
    #[must_use]
    pub fn fingerprint_value(&self) -> &str {
        match self {
            Self::Absent => "absent",
            Self::Version(v) => v,
        }
    }
}

/// Error from a probe.
#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    /// The binary could not be inspected or started.
    #[error("{program}: {source}")]
    Io {
        /// Program.
        program: String,
        /// Cause.
        #[source]
        source: io::Error,
    },
    /// The probe exited non-zero.
    #[error("{program} exited {status}: {stderr}")]
    Failed {
        /// Program.
        program: String,
        /// Exit status.
        status: String,
        /// Trimmed stderr.
        stderr: String,
    },
}

/// Identity of a binary at probe time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryIdentity {
    /// Canonical path.
    pub realpath: PathBuf,
    /// Size in bytes.
    pub size: u64,
    /// Modification time, nanoseconds since the epoch.
    pub mtime_ns: i128,
    /// Device id.
    pub dev: u64,
    /// Inode.
    pub ino: u64,
    /// rustup context hash, for rustup proxies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    identity: BinaryIdentity,
    output: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheFile {
    version: u32,
    entries: BTreeMap<String, Entry>,
}

/// Counts for tests and `doctor`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ToolCacheStats {
    /// Lookups answered from the cache.
    pub hits: u32,
    /// Subprocesses run.
    pub runs: u32,
}

/// The loaded cache.
#[derive(Debug)]
pub struct ToolCache {
    path: PathBuf,
    entries: BTreeMap<String, Entry>,
    changed: BTreeSet<String>,
    stats: ToolCacheStats,
}

/// The first executable `program` in the `PATH` value `path`. Empty and
/// relative entries are skipped.
#[must_use]
pub fn which(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path?)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(program))
        .find(|c| fs::metadata(c).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

fn mtime_ns(md: &fs::Metadata) -> i128 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
}

fn is_rustup_proxy(resolved: &Path, real: &Path) -> bool {
    let named_rustup = real
        .file_name()
        .and_then(OsStr::to_str)
        .is_some_and(|n| n == "rustup" || n.starts_with("rustup-init"));
    if named_rustup {
        return true;
    }
    // rustup-init installs proxies as hard links to `rustup`.
    resolved.parent().is_some_and(|dir| {
        match (fs::metadata(resolved), fs::metadata(dir.join("rustup"))) {
            (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
            _ => false,
        }
    })
}

fn rustup_context(program: &str, env: &JobEnv, cwd: &Path) -> String {
    let mut h = blake3::Hasher::new();
    let mut put = |label: &str, bytes: &[u8]| {
        h.update(label.as_bytes());
        h.update(b"\0");
        h.update(bytes);
        h.update(b"\0");
    };
    put(
        "RUSTUP_TOOLCHAIN",
        env.get("RUSTUP_TOOLCHAIN").map_or(b"-", OsStr::as_bytes),
    );
    let rustup_home = env
        .get("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| env.get("HOME").map(|h| Path::new(h).join(".rustup")));
    if let Some(home) = rustup_home {
        put("home", home.as_os_str().as_bytes());
        put(
            "settings",
            &fs::read(home.join("settings.toml")).unwrap_or_default(),
        );
        let mut names: Vec<_> = fs::read_dir(home.join("toolchains"))
            .map(|rd| rd.filter_map(Result::ok).map(|e| e.file_name()).collect())
            .unwrap_or_default();
        names.sort();
        for name in names {
            let bin = home
                .join("toolchains")
                .join(&name)
                .join("bin")
                .join(program);
            let stat = fs::metadata(&bin).map_or_else(
                |_| "-".to_owned(),
                |m| format!("{} {} {}", m.len(), mtime_ns(&m), m.ino()),
            );
            put(&name.to_string_lossy(), stat.as_bytes());
        }
    }
    'search: for dir in cwd.ancestors() {
        let mut found = false;
        for file in ["rust-toolchain", "rust-toolchain.toml"] {
            let p = dir.join(file);
            if let Ok(bytes) = fs::read(&p) {
                put(&p.to_string_lossy(), &bytes);
                found = true;
            }
        }
        if found {
            break 'search;
        }
    }
    h.finalize().to_hex().to_string()
}

impl BinaryIdentity {
    /// The identity of `resolved` (a `PATH` hit) as probed from `cwd`.
    pub fn of(resolved: &Path, program: &str, env: &JobEnv, cwd: &Path) -> io::Result<Self> {
        let realpath = fs::canonicalize(resolved)?;
        let md = fs::metadata(&realpath)?;
        let context =
            is_rustup_proxy(resolved, &realpath).then(|| rustup_context(program, env, cwd));
        Ok(Self {
            realpath,
            size: md.len(),
            mtime_ns: mtime_ns(&md),
            dev: md.dev(),
            ino: md.ino(),
            context,
        })
    }
}

impl ToolCache {
    /// Loads the cache file; a missing or unreadable file gives an empty
    /// cache (it only saves subprocesses).
    #[must_use]
    pub fn load(path: &Path) -> Self {
        let entries = fsx::read_optional(path)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<CacheFile>(&b).ok())
            .filter(|f| f.version == FILE_VERSION)
            .map(|f| f.entries)
            .unwrap_or_default();
        Self {
            path: path.to_owned(),
            entries,
            changed: BTreeSet::new(),
            stats: ToolCacheStats::default(),
        }
    }

    /// Hit and run counts since load.
    #[must_use]
    pub fn stats(&self) -> ToolCacheStats {
        self.stats
    }

    /// The cached output for `id` and `binary`, or `compute()` stored under
    /// the binary's current identity.
    pub fn cached<E>(
        &mut self,
        id: &str,
        identity: BinaryIdentity,
        compute: impl FnOnce() -> Result<String, E>,
    ) -> Result<String, E> {
        let key = format!("{id}@{}", identity.realpath.display());
        if let Some(e) = self.entries.get(&key)
            && e.identity == identity
        {
            self.stats.hits += 1;
            return Ok(e.output.clone());
        }
        self.stats.runs += 1;
        let output = compute()?;
        self.entries.insert(
            key.clone(),
            Entry {
                identity,
                output: output.clone(),
            },
        );
        self.changed.insert(key);
        Ok(output)
    }

    /// Runs (or recalls) `probe` with the job environment in `cwd` (R74, R75).
    pub fn probe(
        &mut self,
        probe: &Probe,
        env: &JobEnv,
        cwd: &Path,
    ) -> Result<ProbeResult, ProbeError> {
        let Some(resolved) = which(probe.program, env.get("PATH")) else {
            return Ok(ProbeResult::Absent);
        };
        let io_err = |source| ProbeError::Io {
            program: probe.program.to_owned(),
            source,
        };
        let identity = BinaryIdentity::of(&resolved, probe.program, env, cwd).map_err(io_err)?;
        let id = format!("{} {}", probe.id, probe.args.join(" "));
        self.cached(&id, identity, || {
            // Run the PATH name, not the realpath: rustup proxies dispatch on
            // argv[0].
            let mut cmd = Command::new(&resolved);
            env.apply(&mut cmd)
                .args(probe.args)
                .current_dir(cwd)
                .stdin(Stdio::null());
            let out = cmd.output().map_err(io_err)?;
            if !out.status.success() {
                return Err(ProbeError::Failed {
                    program: probe.program.to_owned(),
                    status: out.status.to_string(),
                    stderr: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
                });
            }
            let text = if out.stdout.iter().all(u8::is_ascii_whitespace) {
                out.stderr
            } else {
                out.stdout
            };
            Ok(String::from_utf8_lossy(&text).trim().to_owned())
        })
        .map(ProbeResult::Version)
    }

    /// Writes new entries, merged into the file as it is now (another
    /// process may have saved meanwhile). Atomic rename (R37).
    pub fn save(&mut self) -> io::Result<()> {
        if self.changed.is_empty() {
            return Ok(());
        }
        let mut on_disk = Self::load(&self.path).entries;
        for key in &self.changed {
            if let Some(e) = self.entries.get(key) {
                on_disk.insert(key.clone(), e.clone());
            }
        }
        let file = CacheFile {
            version: FILE_VERSION,
            entries: on_disk,
        };
        let json = serde_json::to_vec_pretty(&file).map_err(io::Error::other)?;
        fsx::write_atomic(&self.path, &json)?;
        self.changed.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn exe(path: &Path, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn which_skips_non_executables_and_relative_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let a = tmp.path().join("a");
        let b = tmp.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::write(a.join("tool"), "not executable").unwrap();
        exe(&b.join("tool"), "echo b");
        let path = std::env::join_paths(["rel".as_ref(), a.as_path(), b.as_path()]).unwrap();
        assert_eq!(which("tool", Some(&path)), Some(b.join("tool")));
        assert_eq!(which("nope", Some(&path)), None);
        assert_eq!(which("tool", None), None);
    }

    #[test]
    fn rustup_proxy_identity_tracks_toolchain_updates() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path();
        let bin = home.join(".cargo/bin");
        exe(&bin.join("rustup"), "echo rustup");
        symlink("rustup", bin.join("rustc")).unwrap();
        let tc = home.join(".rustup/toolchains/stable-x/bin/rustc");
        exe(&tc, "echo 1");
        fs::write(
            home.join(".rustup/settings.toml"),
            "default_toolchain = \"stable-x\"\n",
        )
        .unwrap();
        let env = JobEnv::from_vars([("HOME", home.as_os_str())]);
        let repo = home.join("repo");
        fs::create_dir_all(&repo).unwrap();

        let id1 = BinaryIdentity::of(&bin.join("rustc"), "rustc", &env, &repo).unwrap();
        assert!(id1.context.is_some());
        assert_eq!(
            id1,
            BinaryIdentity::of(&bin.join("rustc"), "rustc", &env, &repo).unwrap()
        );

        // `rustup update` rewrites the toolchain binary, not the proxy.
        exe(&tc, "echo 2 updated toolchain");
        let id2 = BinaryIdentity::of(&bin.join("rustc"), "rustc", &env, &repo).unwrap();
        assert_ne!(id1, id2);

        // A toolchain file in the repo changes the context too.
        fs::write(
            repo.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.90\"\n",
        )
        .unwrap();
        let id3 = BinaryIdentity::of(&bin.join("rustc"), "rustc", &env, &repo).unwrap();
        assert_ne!(id2, id3);

        // A hard-linked proxy is recognised by inode.
        fs::hard_link(bin.join("rustup"), bin.join("cargo")).unwrap();
        assert!(
            BinaryIdentity::of(&bin.join("cargo"), "cargo", &env, &repo)
                .unwrap()
                .context
                .is_some()
        );
        // A plain binary has no context.
        exe(&bin.join("cargo-nextest"), "echo n");
        assert!(
            BinaryIdentity::of(&bin.join("cargo-nextest"), "cargo-nextest", &env, &repo)
                .unwrap()
                .context
                .is_none()
        );
    }
}
