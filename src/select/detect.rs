//! Root detection and the detected config (R45, R57 roots, R59, R60, R65).
//!
//! Roots are looked for at the repo root and one level down, skipping
//! `node_modules`, `dist`, `build`, `target`, `vendor` and dot-dirs:
//!
//! - Rust: a dir with `Cargo.toml`. A root-level `Cargo.toml` makes the
//!   repo root the only Rust root (one level down are its members).
//! - TypeScript/Bun: `package.json` plus `bun.lock` or `bun.lockb`.
//! - Python: `pyproject.toml`.
//!
//! The detected config, used when the policy commit has no `tollgate.toml`:
//!
//! - Rust root: `fmt`, `clippy`, `tests` (nextest), `doctests` (R58).
//! - TypeScript root: setup `bun install --frozen-lockfile` (R45); `biome`
//!   when `@biomejs/biome` is a dependency; `svelte-check` when
//!   `svelte-check` is a dependency or the `check` script runs it, else
//!   `tsc` when there is a `tsconfig.json` and `typescript` is a
//!   dependency; `bun test` when `package.json` has a `test` script (R59).
//!   Tools that are not dependencies get no step and a note: R46 forbids
//!   downloading them.
//! - Python root: setup `uv sync --frozen` when the root has `uv.lock`
//!   (R45); `ruff`, `pyright` (pyright-baseline) and `pytest`
//!   (pytest-baseline) always, as `pre-commit-checks.sh` ran them (R60,
//!   R94, L9).
//!
//! Step names carry the root dir as a prefix outside the repo root.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::config::repo::{RepoConfig, SetupStep, Step, StepKind};
use crate::config::{Tier, units::DurationSpec};
use crate::gitx::{Git, TreeEntry};
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
    /// The files at depth 1 and 2 detection looked at.
    pub files: BTreeSet<PathBuf>,
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

    fn has(&self, root: &Path, name: &str) -> bool {
        self.files.contains(&root.join(name))
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
    let typescript = candidates
        .iter()
        .filter(|d| has(d, "package.json") && (has(d, "bun.lock") || has(d, "bun.lockb")))
        .map(PathBuf::from)
        .collect();
    let python = candidates
        .iter()
        .filter(|d| has(d, "pyproject.toml"))
        .map(PathBuf::from)
        .collect();
    Roots {
        rust,
        typescript,
        python,
        files,
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

fn named(root: &Path, base: &str) -> String {
    if root.as_os_str().is_empty() {
        base.to_owned()
    } else {
        format!("{} {base}", root.display())
    }
}

fn step(root: &Path, base: &str, kind: StepKind, resources: &[&str]) -> Step {
    Step {
        name: named(root, base),
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
        env: BTreeMap::new(),
        env_file: None,
        cache_dirs: Vec::new(),
        inputs: vec!["**".into()],
        exclude_inputs: Vec::new(),
    }
}

fn setup(root: &Path, base: &str, run: &str, when: &[&str]) -> SetupStep {
    SetupStep {
        name: named(root, base),
        run: run.to_owned(),
        cwd: (!root.as_os_str().is_empty()).then(|| root.display().to_string()),
        when: when
            .iter()
            .map(|w| root.join(w).display().to_string())
            .collect(),
        env: BTreeMap::new(),
        timeout: None,
    }
}

fn show(p: &Path) -> String {
    if p.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        p.display().to_string()
    }
}

/// What detection reads from a TypeScript root's `package.json`.
#[derive(Debug, Default)]
struct Package {
    deps: BTreeSet<String>,
    scripts: BTreeMap<String, String>,
}

fn package(text: &str) -> Result<Package, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| e.to_string())?;
    let mut p = Package::default();
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(m) = v[key].as_object() {
            p.deps.extend(m.keys().cloned());
        }
    }
    if let Some(m) = v["scripts"].as_object() {
        p.scripts = m
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
            .collect();
    }
    Ok(p)
}

/// The config used when the policy commit has no `tollgate.toml` (R65),
/// with notes for review. `read` returns a repo-relative file's text.
#[must_use]
pub fn detected_config(
    roots: &Roots,
    read: &dyn Fn(&Path) -> Option<String>,
) -> (RepoConfig, Vec<String>) {
    let mut config = RepoConfig::default();
    let mut notes = Vec::new();
    for r in &roots.rust {
        config.steps.extend([
            step(r, "fmt", StepKind::CargoFmt, &[]),
            step(r, "clippy", StepKind::CargoClippy, &["cpu"]),
            step(r, "tests", StepKind::Nextest, &["cpu"]),
            step(r, "doctests", StepKind::CargoDoctest, &["cpu"]),
        ]);
    }
    for r in &roots.typescript {
        config.setup.push(setup(
            r,
            "bun install",
            "bun install --frozen-lockfile",
            &["package.json", "bun.lock", "bun.lockb"],
        ));
        let pkg = match read(&r.join("package.json")).map(|t| package(&t)) {
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                notes.push(format!(
                    "TypeScript root {}: package.json is not valid JSON ({e}); no steps",
                    show(r)
                ));
                continue;
            }
            None => Package::default(),
        };
        if pkg.deps.contains("@biomejs/biome") {
            config.steps.push(step(r, "biome", StepKind::Biome, &[]));
        } else {
            notes.push(format!(
                "TypeScript root {}: @biomejs/biome is not a dependency; no biome step (R46: no downloads)",
                show(r)
            ));
        }
        let svelte = pkg.deps.contains("svelte-check")
            || pkg
                .scripts
                .get("check")
                .is_some_and(|s| s.contains("svelte-check"));
        if svelte {
            config
                .steps
                .push(step(r, "svelte-check", StepKind::SvelteCheck, &["cpu"]));
        } else if roots.has(r, "tsconfig.json") {
            if pkg.deps.contains("typescript") {
                config.steps.push(step(r, "tsc", StepKind::Tsc, &["cpu"]));
            } else {
                notes.push(format!(
                    "TypeScript root {}: tsconfig.json but typescript is not a dependency; no tsc step (R46: no downloads)",
                    show(r)
                ));
            }
        }
        if pkg.scripts.contains_key("test") {
            config
                .steps
                .push(step(r, "bun test", StepKind::BunTest, &["cpu"]));
        }
    }
    for r in &roots.python {
        if roots.has(r, "uv.lock") {
            config.setup.push(setup(
                r,
                "uv sync",
                "uv sync --frozen",
                &["pyproject.toml", "uv.lock"],
            ));
        } else {
            notes.push(format!(
                "Python root {}: no uv.lock, so no uv sync setup step (R45); ruff, pyright and pytest must be on the job PATH",
                show(r)
            ));
        }
        config.steps.extend([
            step(r, "ruff", StepKind::Ruff, &[]),
            step(r, "pyright", StepKind::PyrightBaseline, &["cpu"]),
            step(r, "pytest", StepKind::PytestBaseline, &["cpu"]),
        ]);
    }
    for r in roots.other() {
        if r.as_os_str().is_empty() {
            notes.push(
                "a TypeScript or Python root at the repo root makes every path code: built-in docs-only paths (R61) never apply; list docs globs in select.docs_only".to_owned(),
            );
            break;
        }
    }
    (config, notes)
}

/// Detection on a tree (jobs, `config --effective`): files are read from
/// the tree's blobs.
#[must_use]
pub fn detect_tree(git: &Git, entries: &[TreeEntry]) -> (RepoConfig, Vec<String>) {
    let read = |p: &Path| {
        let e = entries.iter().find(|e| e.path == p && e.kind == "blob")?;
        let bytes = git.run(["cat-file", "blob", e.oid.as_str()]).ok()?;
        String::from_utf8(bytes).ok()
    };
    detected_config(&roots_from_tree(entries), &read)
}

/// L2, D5: adds to `tree` (detection on the tree under test) every setup
/// and step that `policy` (detection on the policy commit) has and `tree`
/// lacks, by name, each with a note. Removing a detected step is a policy
/// change: a branch that deletes a test script, a linter dependency or a
/// root still runs those steps, which then fail with a setup error, until
/// the change merges to a full ref. Steps that only the tree has (a new
/// root) stay.
pub fn keep_policy_steps(tree: &mut RepoConfig, policy: RepoConfig, notes: &mut Vec<String>) {
    for s in policy.setup {
        if !tree.setup.iter().any(|t| t.name == s.name) {
            notes.push(format!(
                "setup {:?} comes from detection on the policy commit; this tree no longer gets it from detection (L2)",
                s.name
            ));
            tree.setup.push(s);
        }
    }
    for s in policy.steps {
        if !tree.steps.iter().any(|t| t.name == s.name) {
            notes.push(format!(
                "step {:?} comes from detection on the policy commit; this tree no longer gets it from detection, and removing a step applies only after it merges to a full ref (L2)",
                s.name
            ));
            tree.steps.push(s);
        }
    }
}

/// Detection on a work dir (`run --here`, `config init`, `config --check`).
pub fn detect_dir(root: &Path) -> std::io::Result<(RepoConfig, Vec<String>)> {
    let roots = roots_from_dir(root)?;
    let read = |p: &Path| std::fs::read_to_string(root.join(p)).ok();
    Ok(detected_config(&roots, &read))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(paths: &[&str]) -> Roots {
        roots_from_paths(paths.iter().map(Path::new))
    }

    #[test]
    fn policy_commit_steps_stay_l2_r65() {
        let read = |_: &Path| -> Option<String> { None };
        let (base, _) = detected_config(&roots(&["Cargo.toml", "py/pyproject.toml"]), &read);
        let (mut tree, _) = detected_config(
            &roots(&["Cargo.toml", "web/package.json", "web/bun.lock"]),
            &read,
        );
        let mut notes = Vec::new();
        keep_policy_steps(&mut tree, base, &mut notes);
        let names: Vec<&str> = tree.steps.iter().map(|s| s.name.as_str()).collect();
        for want in ["fmt", "tests", "py ruff", "py pytest"] {
            assert!(names.contains(&want), "{want}: {names:?}");
        }
        assert_eq!(names.iter().filter(|n| **n == "fmt").count(), 1);
        assert!(tree.setup.iter().any(|s| s.name == "web bun install"));
        assert!(
            notes
                .iter()
                .any(|n| n.contains("\"py ruff\"") && n.contains("policy commit"))
        );
        assert!(!notes.iter().any(|n| n.contains("\"fmt\"")));
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

    fn none(_: &Path) -> Option<String> {
        None
    }

    #[test]
    fn detected_rust_steps_r65() {
        let (c, notes) = detected_config(&roots(&["Cargo.toml"]), &none);
        let names: Vec<_> = c.steps.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["fmt", "clippy", "tests", "doctests"]);
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert!(notes.is_empty(), "{notes:?}");
        let (n, _) = detected_config(&roots(&["rust/Cargo.toml"]), &none);
        assert_eq!(n.steps[0].name, "rust fmt");
        assert_eq!(n.steps[0].cwd.as_deref(), Some("rust"));
    }

    fn names(c: &RepoConfig) -> Vec<(String, StepKind)> {
        c.steps.iter().map(|s| (s.name.clone(), s.kind)).collect()
    }

    #[test]
    fn detected_typescript_steps_follow_package_json_r59_r45_r65() {
        let files: BTreeMap<PathBuf, String> = [
            (
                "dashboard/package.json",
                r#"{"scripts":{"check":"svelte-kit sync && svelte-check","test":"vitest"},"devDependencies":{"@biomejs/biome":"2","svelte-check":"4"}}"#,
            ),
            (
                "web/package.json",
                r#"{"scripts":{"build":"x"},"devDependencies":{"typescript":"6"}}"#,
            ),
            ("bare/package.json", r#"{"name":"bare"}"#),
        ]
        .into_iter()
        .map(|(p, t)| (PathBuf::from(p), t.to_owned()))
        .collect();
        let read = |p: &Path| files.get(p).cloned();
        let r = roots(&[
            "dashboard/package.json",
            "dashboard/bun.lock",
            "dashboard/tsconfig.json",
            "web/package.json",
            "web/bun.lockb",
            "web/tsconfig.json",
            "bare/package.json",
            "bare/bun.lock",
            "bare/tsconfig.json",
        ]);
        let (c, notes) = detected_config(&r, &read);
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert_eq!(
            names(&c),
            [
                ("dashboard biome".to_owned(), StepKind::Biome),
                ("dashboard svelte-check".to_owned(), StepKind::SvelteCheck),
                ("dashboard bun test".to_owned(), StepKind::BunTest),
                ("web tsc".to_owned(), StepKind::Tsc),
            ]
        );
        let setup: Vec<_> = c
            .setup
            .iter()
            .map(|s| (s.name.as_str(), s.run.as_str()))
            .collect();
        assert_eq!(
            setup,
            [
                ("bare bun install", "bun install --frozen-lockfile"),
                ("dashboard bun install", "bun install --frozen-lockfile"),
                ("web bun install", "bun install --frozen-lockfile"),
            ]
        );
        assert_eq!(c.setup[1].cwd.as_deref(), Some("dashboard"));
        assert_eq!(
            c.setup[1].when,
            [
                "dashboard/package.json",
                "dashboard/bun.lock",
                "dashboard/bun.lockb"
            ]
        );
        let text = notes.join("\n");
        assert!(
            text.contains("TypeScript root bare: tsconfig.json but typescript is not a dependency"),
            "{text}"
        );
        assert!(
            text.contains("TypeScript root web: @biomejs/biome is not a dependency"),
            "{text}"
        );
    }

    #[test]
    fn detected_python_steps_and_uv_sync_r60_r45_r65() {
        let (c, notes) = detected_config(
            &roots(&["pyproject.toml", "uv.lock", "tools/pyproject.toml"]),
            &none,
        );
        assert!(c.validate().is_ok(), "{:?}", c.validate());
        assert_eq!(
            names(&c),
            [
                ("ruff".to_owned(), StepKind::Ruff),
                ("pyright".to_owned(), StepKind::PyrightBaseline),
                ("pytest".to_owned(), StepKind::PytestBaseline),
                ("tools ruff".to_owned(), StepKind::Ruff),
                ("tools pyright".to_owned(), StepKind::PyrightBaseline),
                ("tools pytest".to_owned(), StepKind::PytestBaseline),
            ]
        );
        assert_eq!(c.setup.len(), 1);
        assert_eq!(c.setup[0].run, "uv sync --frozen");
        assert_eq!(c.setup[0].cwd, None);
        assert_eq!(c.setup[0].when, ["pyproject.toml", "uv.lock"]);
        let text = notes.join("\n");
        assert!(text.contains("Python root tools: no uv.lock"), "{text}");
        assert!(
            text.contains("built-in docs-only paths (R61) never apply"),
            "{text}"
        );
    }
}
