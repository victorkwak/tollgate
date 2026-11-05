//! Real TypeScript and Python tools for tests, with no network.
//!
//! Tools that are not installed make a test skip with a `SKIP` line. Tests
//! never download: packages come from what this machine already has, read
//! only:
//!
//! - `bun`, `uv`, `pyright`: on the test's `PATH`.
//! - biome: the native binary from bun's install cache
//!   (`~/.bun/install/cache/@biomejs/cli-<platform>@<version>`), wrapped in
//!   a local package with no dependencies.
//! - TypeScript: the package of the `tsc` on `PATH` (its `bin` and `lib`),
//!   copied into a local package with no dependencies.
//! - Python wheels (pytest and its dependencies, ruff): rebuilt from the
//!   unpacked wheels in uv's cache (`~/.cache/uv/wheels-v5/pypi/<name>`)
//!   into a dir the test project lists as its only package index.
//!
//! Projects reach these local packages through a symlink committed in the
//! repo (`vendor/<pkg>`, `wheels`): lockfiles store paths relative to the
//! project, and the symlink resolves the same way in a verify checkout.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

/// Prints why a test does not run.
pub fn skip(test: &str, why: &str) {
    eprintln!("SKIP {test}: {why}");
}

/// `program` on the test process's `PATH`.
pub fn which(program: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|d| d.join(program))
        .find(|p| p.is_file())
}

fn real_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Copies with `cp -R` (a child process: see `write_exe` on ETXTBSY).
pub fn copy(from: &Path, to: &Path) {
    if let Some(d) = to.parent() {
        std::fs::create_dir_all(d).unwrap();
    }
    let st = Command::new("cp")
        .arg("-R")
        .arg(from)
        .arg(to)
        .status()
        .unwrap();
    assert!(st.success(), "cp {} {}", from.display(), to.display());
}

/// A sortable version: numeric-aware (`2.10` after `2.9`).
type VersionKey = Vec<(u64, String)>;

/// Numeric-aware version order (`2.10` after `2.9`).
fn version_key(v: &str) -> VersionKey {
    v.split(['.', '-', '+'])
        .map(|part| {
            let digits: String = part.chars().take_while(char::is_ascii_digit).collect();
            (digits.parse().unwrap_or(0), part[digits.len()..].to_owned())
        })
        .collect()
}

/// The bun cache dir name of biome's native package for this platform.
fn biome_platform() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("cli-linux-x64"),
        ("linux", "aarch64") => Some("cli-linux-arm64"),
        ("macos", "aarch64") => Some("cli-darwin-arm64"),
        ("macos", "x86_64") => Some("cli-darwin-x64"),
        _ => None,
    }
}

/// The newest cached biome native binary.
pub fn biome_binary() -> Option<PathBuf> {
    let dir = real_home()?.join(".bun/install/cache/@biomejs");
    let prefix = format!("{}@", biome_platform()?);
    let mut found: Vec<(VersionKey, PathBuf)> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let version = name.strip_prefix(&prefix)?.split("@@").next()?.to_owned();
            let bin = e.path().join("biome");
            bin.is_file().then(|| (version_key(&version), bin))
        })
        .collect();
    found.sort();
    found.pop().map(|(_, p)| p)
}

/// The package dir of the `tsc` on `PATH` (`<pkg>/bin/tsc`, `<pkg>/lib`).
pub fn typescript_dir() -> Option<PathBuf> {
    let tsc = which("tsc")?.canonicalize().ok()?;
    let pkg = tsc.parent()?.parent()?.to_owned();
    pkg.join("lib/tsc.js").is_file().then_some(pkg)
}

/// Writes a local npm package `name` with `bin` entries into `dir`.
fn package_json(dir: &Path, name: &str, bins: &[(&str, &str)]) {
    let bins: serde_json::Map<String, serde_json::Value> = bins
        .iter()
        .map(|(k, v)| ((*k).to_owned(), serde_json::Value::from(*v)))
        .collect();
    std::fs::write(
        dir.join("package.json"),
        serde_json::to_string(&serde_json::json!({
            "name": name,
            "version": "0.0.0-local",
            "bin": bins,
        }))
        .unwrap(),
    )
    .unwrap();
}

/// Local packages `@biomejs/biome` and `typescript` under `dir` (no
/// dependencies, so `bun install` never contacts a registry). `None` when
/// either tool is not on this machine.
pub fn ts_packages(dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let biome = biome_binary()?;
    let ts = typescript_dir()?;
    let b = dir.join("biome");
    std::fs::create_dir_all(&b).unwrap();
    copy(&biome, &b.join("biome"));
    package_json(&b, "@biomejs/biome", &[("biome", "biome")]);
    let t = dir.join("typescript");
    std::fs::create_dir_all(t.join("bin")).unwrap();
    copy(&ts.join("bin/tsc"), &t.join("bin/tsc"));
    copy(&ts.join("lib"), &t.join("lib"));
    package_json(&t, "typescript", &[("tsc", "bin/tsc")]);
    Some((b, t))
}

/// The uv cache dir of this machine (read only).
fn uv_cache() -> Option<PathBuf> {
    std::env::var_os("UV_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(|x| PathBuf::from(x).join("uv")))
        .or_else(|| real_home().map(|h| h.join(".cache/uv")))
}

/// True when a wheel tag can install here.
fn tag_fits(tag: &str) -> bool {
    if tag.ends_with("-none-any") {
        return true;
    }
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", arch) => tag.contains("manylinux") && tag.contains(arch),
        ("macos", "aarch64") => {
            tag.contains("macosx") && (tag.contains("arm64") || tag.contains("universal2"))
        }
        ("macos", arch) => {
            tag.contains("macosx") && (tag.contains(arch) || tag.contains("universal2"))
        }
        _ => false,
    }
}

/// Rebuilds the newest cached wheel of `name` into `out`. `None` when uv's
/// cache has none for this platform.
fn wheel(cache: &Path, name: &str, out: &Path) -> Option<()> {
    let dir = cache.join("wheels-v5/pypi").join(name);
    let mut found: Vec<(VersionKey, String, PathBuf)> = std::fs::read_dir(&dir)
        .ok()?
        .flatten()
        .filter_map(|e| {
            let file = e.file_name().to_string_lossy().into_owned();
            if file.contains('.') && (file.ends_with(".http") || file.ends_with(".msgpack")) {
                return None;
            }
            let (version, tag) = file.split_once('-')?;
            let unpacked = std::fs::canonicalize(e.path()).ok()?;
            (tag_fits(tag) && unpacked.is_dir())
                .then(|| (version_key(version), file.clone(), unpacked))
        })
        .collect();
    found.sort();
    let (_, file, unpacked) = found.pop()?;
    let (version, tag) = file.split_once('-')?;
    let whl = out.join(format!("{}-{version}-{tag}.whl", name.replace('-', "_")));
    let entries: Vec<_> = std::fs::read_dir(&unpacked)
        .ok()?
        .flatten()
        .map(|e| e.file_name())
        .collect();
    let st = Command::new("python3")
        .current_dir(&unpacked)
        .args(["-m", "zipfile", "-c"])
        .arg(&whl)
        .args(&entries)
        .status()
        .ok()?;
    st.success().then_some(())
}

/// pytest and the packages it needs.
pub const PYTEST: &[&str] = &["pytest", "iniconfig", "packaging", "pluggy", "pygments"];

/// Rebuilds the wheels of `names` from uv's cache into `out`. `None` when
/// one is missing (the test then skips).
pub fn wheels(names: &[&str], out: &Path) -> Option<()> {
    let cache = uv_cache()?;
    which("python3")?;
    std::fs::create_dir_all(out).ok()?;
    for n in names {
        wheel(&cache, n, out)?;
    }
    Some(())
}

/// The PEP 508 marker of this platform, so `uv lock` resolves only for it.
pub fn platform_marker() -> String {
    let platform = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let machine = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => "arm64",
        (_, arch) => arch,
    };
    format!("sys_platform == '{platform}' and platform_machine == '{machine}'")
}

/// A `pyproject.toml` whose only package source is the `wheels` dir next to
/// it (a symlink to the rebuilt wheels).
pub fn pyproject(name: &str, dev: &[&str]) -> String {
    let dev: Vec<String> = dev.iter().map(|d| format!("{d:?}")).collect();
    format!(
        "[project]\nname = {name:?}\nversion = \"0.1.0\"\nrequires-python = \">=3.11\"\n\n[dependency-groups]\ndev = [{}]\n\n[tool.uv]\nfind-links = [\"wheels\"]\nno-index = true\nenvironments = [{:?}]\n",
        dev.join(", "),
        platform_marker()
    )
}

/// Environment for `uv` and `bun` in a sandbox: offline, no interpreter
/// downloads, caches under the sandbox.
pub fn offline_env(root: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("UV_OFFLINE", "1".into()),
        ("UV_PYTHON_DOWNLOADS", "never".into()),
        ("UV_NO_PROGRESS", "1".into()),
        ("UV_CACHE_DIR", root.join("uv-cache")),
        ("BUN_INSTALL_CACHE_DIR", root.join("bun-cache")),
        ("NO_COLOR", "1".into()),
    ]
}

/// The host config `[job]` part that puts `programs`' dirs on the job PATH
/// and keeps uv offline (R52).
pub fn job_config(programs: &[&Path]) -> String {
    let mut dirs: Vec<String> = Vec::new();
    for p in programs {
        let d = p.parent().unwrap().display().to_string();
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    let dirs: Vec<String> = dirs.iter().map(|d| format!("{d:?}")).collect();
    format!(
        "[job]\npath_prepend = [{}]\n[job.env]\nUV_OFFLINE = \"1\"\nUV_PYTHON_DOWNLOADS = \"never\"\nUV_NO_PROGRESS = \"1\"\nNO_COLOR = \"1\"\n",
        dirs.join(", ")
    )
}

/// Runs `program args` in `dir` with the sandbox `env` plus `extra`;
/// panics with the output on failure.
pub fn run(
    program: &Path,
    args: &[&str],
    dir: &Path,
    env: &tollgate::env::EnvSnapshot,
    extra: &[(&str, PathBuf)],
) -> String {
    let mut cmd = Command::new(program);
    cmd.env_clear().current_dir(dir).args(args);
    for (k, v) in env.iter() {
        cmd.env(k, v);
    }
    for (k, v) in extra {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "{} {args:?} in {}: {text}",
        program.display(),
        dir.display()
    );
    text
}
