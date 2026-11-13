//! Finds the git commit of the build for `tollgate --version` (R97).
//!
//! In a git checkout: `git rev-parse` of `HEAD` (12 hex digits), with
//! `-dirty` when the checkout has changes (`git status`). In a package from crates.io
//! there is no git dir: `cargo package` writes the commit to
//! `.cargo_vcs_info.json`, which is read instead. With neither, no commit is
//! set and the version is the package version alone.
//!
//! The commit is for people and for `doctor`. It never goes into a record
//! or a fingerprint (R74): that would void every stored result on each
//! build.

use std::path::Path;
use std::process::Command;

/// How many hex digits of the commit the version shows.
const COMMIT_DIGITS: usize = 12;

/// Runs `git <args>` in `dir`, with no optional lock (so `status` writes no
/// index) and returns its trimmed stdout when it exits 0.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// `text` when it is a full hex object id, cut to [`COMMIT_DIGITS`].
fn short(text: &str) -> Option<String> {
    (text.len() >= COMMIT_DIGITS && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| text[..COMMIT_DIGITS].to_ascii_lowercase())
}

/// The commit of the git checkout at `dir`, when `dir` is the top of one.
fn from_git(dir: &Path) -> Option<String> {
    // Only the checkout this package is the top of: a package unpacked
    // inside another repo must not take that repo's commit.
    let top = git(dir, &["rev-parse", "--show-toplevel"])?;
    if Path::new(&top).canonicalize().ok()? != dir.canonicalize().ok()? {
        return None;
    }
    let commit = short(&git(dir, &["rev-parse", "HEAD"])?)?;
    // A new commit or checkout moves these; build again then. The index
    // is not watched: it changes on every `git add`, and each run of this
    // script builds the whole crate again.
    for path in ["HEAD", "logs/HEAD"] {
        if let Some(p) = git(dir, &["rev-parse", "--git-path", path]) {
            println!("cargo:rerun-if-changed={}", dir.join(p).display());
        }
    }
    // Ignored files (`target/`) do not count.
    let dirty = git(dir, &["status", "--porcelain"]).is_some_and(|s| !s.is_empty());
    Some(if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    })
}

/// The commit `cargo package` recorded: `{"git":{"sha1":"<oid>", ...}}`.
fn from_vcs_info(dir: &Path) -> Option<String> {
    let path = dir.join(".cargo_vcs_info.json");
    println!("cargo:rerun-if-changed={}", path.display());
    let text = std::fs::read_to_string(path).ok()?;
    let rest = &text[text.find("\"sha1\"")? + "\"sha1\"".len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let oid = rest.strip_prefix('"')?.split('"').next()?;
    let commit = short(oid)?;
    Some(
        if text.contains("\"dirty\": true") || text.contains("\"dirty\":true") {
            format!("{commit}-dirty")
        } else {
            commit
        },
    )
}

fn main() {
    // The sources decide `-dirty`: an edit builds the crate anyway, and
    // this script then looks again.
    for path in ["build.rs", "Cargo.toml", "Cargo.lock", "src"] {
        println!("cargo:rerun-if-changed={path}");
    }
    let dir = std::env::var_os("CARGO_MANIFEST_DIR").unwrap_or_default();
    let dir = Path::new(&dir);
    if let Some(commit) = from_git(dir).or_else(|| from_vcs_info(dir)) {
        println!("cargo:rustc-env=TOLLGATE_GIT_COMMIT={commit}");
        // `<version> (<commit>)`, joined here: a const cannot format.
        let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
        println!("cargo:rustc-env=TOLLGATE_BUILD={version} ({commit})");
    }
}
