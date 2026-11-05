//! Root detection and the detected config (R57 roots, R59, R60, R65).
//!
//! Roots are looked for at the repo root and one level down, skipping
//! `node_modules`, `dist`, `build`, `target`, `vendor` and dot-dirs:
//!
//! - Rust: a dir with `Cargo.toml`. A root-level `Cargo.toml` makes the
//!   repo root the only Rust root (one level down are its members).
//! - TypeScript/Bun: `package.json` plus `bun.lock` or `bun.lockb`.
//! - Python: `pyproject.toml`.
//!
//! The detected config has the four Rust steps per Rust root. The
//! TypeScript and Python step kinds and their setup steps (R45, R59, R60)
//! are not built yet: detection names those roots in its notes and adds no
//! steps for them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::config::repo::{RepoConfig, Step, StepKind};
use crate::config::{Tier, units::DurationSpec};
use crate::gitx::TreeEntry;
use crate::ids::ResourceName;

const SKIP_DIRS: &[&str] = &["node_modules", "dist", "build", "target", "vendor"];

/// Roots found in a tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Roots {
    /// Cargo workspace or package roots.
    pub rust: Vec<PathBuf>,
    /// Bun projects.
    pub typescript: Vec<PathBuf>,
    /// Python projects.
    pub python: Vec<PathBuf>,
}

impl Roots {
    /// TS and Python roots: code roots for docs-only (R61) and selection.
    #[must_use]
    pub fn other(&self) -> Vec<PathBuf> {
        self.typescript
            .iter()
            .chain(&self.python)
            .cloned()
            .collect()
    }
}

fn skipped(dir: &str) -> bool {
    dir.starts_with('.') || SKIP_DIRS.contains(&dir)
}

/// Detects roots from repo-relative file paths (only depth 1 and 2 matter).
#[must_use]
pub fn roots_from_paths<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Roots {
    let mut files: BTreeSet<PathBuf> = BTreeSet::new();
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for p in paths {
        let parts: Vec<_> = p.components().collect();
        match parts.as_slice() {
            [_] => {
                files.insert(p.to_owned());
            }
            [d, _] => {
                if let Some(d) = d.as_os_str().to_str()
                    && !skipped(d)
                {
                    dirs.insert(d.to_owned());
                    files.insert(p.to_owned());
                }
            }
            _ => {}
        }
    }
    let has = |dir: &str, name: &str| files.contains(&Path::new(dir).join(name));
    let candidates: Vec<&str> = std::iter::once("")
        .chain(dirs.iter().map(String::as_str))
        .collect();
    let rust = if has("", "Cargo.toml") {
        vec![PathBuf::new()]
    } else {
        candidates
            .iter()
            .filter(|d| has(d, "Cargo.toml"))
            .map(PathBuf::from)
            .collect()
    };
    Roots {
        rust,
        typescript: candidates
            .iter()
            .filter(|d| has(d, "package.json") && (has(d, "bun.lock") || has(d, "bun.lockb")))
            .map(PathBuf::from)
            .collect(),
        python: candidates
            .iter()
            .filter(|d| has(d, "pyproject.toml"))
            .map(PathBuf::from)
            .collect(),
    }
}

/// Detects roots from a tree listing.
#[must_use]
pub fn roots_from_tree(entries: &[TreeEntry]) -> Roots {
    roots_from_paths(entries.iter().map(|e| e.path.as_path()))
}

/// Detects roots from the files of a working dir (`run --here`, `config`).
pub fn roots_from_dir(root: &Path) -> std::io::Result<Roots> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = PathBuf::from(entry.file_name());
        if entry.file_type()?.is_dir() {
            if name.to_str().is_some_and(skipped) {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(entry.path()) {
                for sub in rd.flatten() {
                    paths.push(name.join(sub.file_name()));
                }
            }
        } else {
            paths.push(name);
        }
    }
    Ok(roots_from_paths(paths.iter().map(PathBuf::as_path)))
}

fn step(root: &Path, base: &str, kind: StepKind, resources: &[&str]) -> Step {
    let name = if root.as_os_str().is_empty() {
        base.to_owned()
    } else {
        format!("{} {base}", root.display())
    };
    Step {
        name,
        kind,
        run: None,
        cwd: (!root.as_os_str().is_empty()).then(|| root.display().to_string()),
        tiers: vec![Tier::Fast, Tier::Full],
        when: Vec::new(),
        resources: resources
            .iter()
            .map(|r| ResourceName::parse(r).expect("built-in resource name"))
            .collect(),
        timeout: None::<DurationSpec>,
        grace: None,
        only_on: Vec::new(),
        env: std::collections::BTreeMap::new(),
        env_file: None,
        cache_dirs: Vec::new(),
        inputs: vec!["**".into()],
        exclude_inputs: Vec::new(),
    }
}

/// The config used when the policy commit has no `tollgate.toml` (R65),
/// with notes on roots that get no steps yet.
#[must_use]
pub fn detected_config(roots: &Roots) -> (RepoConfig, Vec<String>) {
    let mut config = RepoConfig::default();
    for r in &roots.rust {
        config.steps.extend([
            step(r, "fmt", StepKind::CargoFmt, &[]),
            step(r, "clippy", StepKind::CargoClippy, &["cpu"]),
            step(r, "tests", StepKind::Nextest, &["cpu"]),
            step(r, "doctests", StepKind::CargoDoctest, &["cpu"]),
        ]);
    }
    let mut notes = Vec::new();
    let show = |p: &Path| {
        if p.as_os_str().is_empty() {
            ".".to_owned()
        } else {
            p.display().to_string()
        }
    };
    for r in &roots.typescript {
        notes.push(format!(
            "TypeScript root {}: biome/tsc/bun-test detection is not built yet; no steps",
            show(r)
        ));
    }
    for r in &roots.python {
        notes.push(format!(
            "Python root {}: ruff/pyright/pytest detection is not built yet; no steps",
            show(r)
        ));
    }
    (config, notes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(paths: &[&str]) -> Roots {
        roots_from_paths(paths.iter().map(Path::new))
    }

    #[test]
    fn root_and_one_level_r65() {
        let r = roots(&[
            "Cargo.toml",
            "crates/a/Cargo.toml",
            "dashboard/package.json",
            "dashboard/bun.lock",
            "tools/pyproject.toml",
            "node_modules/x/package.json",
            ".hidden/pyproject.toml",
            "web/package.json",
        ]);
        assert_eq!(r.rust, [PathBuf::new()]);
        assert_eq!(r.typescript, [PathBuf::from("dashboard")]);
        assert_eq!(r.python, [PathBuf::from("tools")]);
        let nested = roots(&["rust/Cargo.toml", "target/Cargo.toml", "README.md"]);
        assert_eq!(nested.rust, [PathBuf::from("rust")]);
    }

    #[test]
    fn detected_rust_steps_r65() {
        let (c, notes) = detected_config(&roots(&["Cargo.toml", "app/pyproject.toml"]));
        let names: Vec<_> = c.steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["fmt", "clippy", "tests", "doctests"]);
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert_eq!(notes.len(), 1);
        let (n, _) = detected_config(&roots(&["rust/Cargo.toml"]));
        assert_eq!(n.steps[0].name, "rust fmt");
        assert_eq!(n.steps[0].cwd.as_deref(), Some("rust"));
    }
}
