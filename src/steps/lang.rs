//! TypeScript/Bun (R59) and Python (R60, R94) step kinds: their command
//! lines, the project tools they use (R46) and the files a `fast` job lints.
//!
//! Tools come from the project, never from a download (R46):
//!
//! - `biome`, `tsc`, `svelte-check`: `node_modules/.bin/<tool>` of the root
//!   (or of a parent dir inside the checkout, for hoisted workspaces), made
//!   by the setup step `bun install --frozen-lockfile` (R45).
//! - `bun-test`: `bun run test`. `svelte-check` runs `bun run check` when the
//!   root's `check` script calls `svelte-check` (it usually runs
//!   `svelte-kit sync` first), else `node_modules/.bin/svelte-check`.
//! - `ruff`: `uv run --no-sync ruff check` and `ruff format --check`.
//! - `pyright-baseline`, `pytest-baseline`: `tollgate __step <kind>`, which
//!   runs `uv run --no-sync pyright|pytest` and applies the baseline of the
//!   policy commit ([`super::baseline`]).
//!
//! A tool that is not there is verdict `error`, cause `setup` (R46).
//!
//! In `fast`, `biome` and `ruff` lint only the changed files under their
//! root ([`lint_pick`]); a change to a file that configures them makes them
//! lint the whole root. The other kinds always check the whole root and are
//! skipped when nothing under the root changed (R59, R60).

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::config::repo::StepKind;

use super::{Invocation, Scope};

/// File extensions `ruff` lints in a `fast` job (its default include set).
const RUFF_EXTENSIONS: &[&str] = &["py", "pyi", "ipynb"];

/// File names that configure `biome`: a change to one at any depth under
/// the root makes a `fast` job lint the whole root.
const BIOME_TRIGGERS: &[&str] = &[
    "biome.json",
    "biome.jsonc",
    ".biome.json",
    ".biome.jsonc",
    "package.json",
    "bun.lock",
    "bun.lockb",
    ".editorconfig",
    ".gitignore",
];

/// File names that configure `ruff` (same rule as [`BIOME_TRIGGERS`]).
const RUFF_TRIGGERS: &[&str] = &[
    "pyproject.toml",
    "ruff.toml",
    ".ruff.toml",
    "uv.lock",
    ".gitignore",
];

/// True for the TypeScript/Bun kinds (R59).
#[must_use]
pub fn is_ts(kind: StepKind) -> bool {
    matches!(
        kind,
        StepKind::Biome | StepKind::Tsc | StepKind::SvelteCheck | StepKind::BunTest
    )
}

/// True for the Python kinds (R60).
#[must_use]
pub fn is_python(kind: StepKind) -> bool {
    matches!(
        kind,
        StepKind::Ruff | StepKind::PyrightBaseline | StepKind::PytestBaseline
    )
}

/// True for the kinds that lint only the changed files in `fast`.
#[must_use]
pub fn is_file_scoped(kind: StepKind) -> bool {
    matches!(kind, StepKind::Biome | StepKind::Ruff)
}

/// What a file-scoped linter checks in a `fast` job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LintPick {
    /// Nothing under the root changed.
    Untouched,
    /// Only deletions or files the tool does not lint changed.
    Nothing,
    /// A config file changed: the whole root.
    Whole,
    /// These repo-relative files.
    Files(BTreeSet<String>),
}

/// The files a `fast` job lints with `kind` under `root`: the changed code
/// paths under it that still exist (`deleted` lists removals), filtered by
/// the tool's file types; the whole root when one of them configures the
/// tool.
#[must_use]
pub fn lint_pick(
    kind: StepKind,
    root: &Path,
    code_paths: &[PathBuf],
    deleted: &BTreeSet<PathBuf>,
) -> LintPick {
    let under: Vec<&PathBuf> = code_paths.iter().filter(|p| p.starts_with(root)).collect();
    if under.is_empty() {
        return LintPick::Untouched;
    }
    let triggers = match kind {
        StepKind::Ruff => RUFF_TRIGGERS,
        _ => BIOME_TRIGGERS,
    };
    let configures = |p: &Path| {
        p.file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|n| triggers.contains(&n))
    };
    if under.iter().any(|p| configures(p)) {
        return LintPick::Whole;
    }
    let files: BTreeSet<String> = under
        .into_iter()
        .filter(|p| !deleted.contains(*p))
        .filter(|p| match kind {
            StepKind::Ruff => p
                .extension()
                .and_then(OsStr::to_str)
                .is_some_and(|e| RUFF_EXTENSIONS.contains(&e)),
            _ => true,
        })
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    if files.is_empty() {
        LintPick::Nothing
    } else {
        LintPick::Files(files)
    }
}

/// What the TypeScript and Python command lines need.
#[derive(Debug, Clone, Copy)]
pub struct LangCtx<'a> {
    /// The step's root dir (absolute, in the checkout or CI work dir).
    pub root_dir: &'a Path,
    /// The checkout (or work dir) root: `node_modules` and `.venv` are
    /// looked for in the root and its parents up to here.
    pub top: &'a Path,
    /// The job `PATH` (R52).
    pub path: Option<&'a OsStr>,
    /// The tollgate binary, for `__step`.
    pub tollgate: &'a Path,
    /// The policy commit's baseline file, written into the job dir (R94).
    pub baseline: Option<&'a Path>,
    /// Where `__step` writes its findings for the report (R91).
    pub findings: &'a Path,
}

/// The dirs from `dir` up to `top` (both included); only `dir` when it is
/// not under `top`.
fn up_to<'p>(dir: &'p Path, top: &'p Path) -> impl Iterator<Item = &'p Path> {
    let under = dir.starts_with(top);
    dir.ancestors()
        .take_while(move |a| !under || a.starts_with(top))
        .take(if under { usize::MAX } else { 1 })
}

fn is_file(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_file())
}

/// `node_modules/.bin/<tool>` in the root or a parent up to the top.
#[must_use]
pub fn node_bin(ctx: &LangCtx<'_>, tool: &str) -> Option<PathBuf> {
    up_to(ctx.root_dir, ctx.top)
        .map(|d| d.join("node_modules/.bin").join(tool))
        .find(|p| is_file(p))
}

/// `<program>` on the `PATH` value `path`.
#[must_use]
pub fn on_path(path: Option<&OsStr>, program: &str) -> Option<PathBuf> {
    std::env::split_paths(path?)
        .map(|d| d.join(program))
        .find(|p| is_file(p))
}

/// Where `uv run --no-sync <tool>` finds `tool`: the project's `.venv/bin`
/// (in the root or a parent up to the top), else the job `PATH`.
#[must_use]
pub fn python_tool(ctx: &LangCtx<'_>, tool: &str) -> Option<PathBuf> {
    up_to(ctx.root_dir, ctx.top)
        .map(|d| d.join(".venv/bin").join(tool))
        .find(|p| is_file(p))
        .or_else(|| on_path(ctx.path, tool))
}

/// True when the root's `package.json` has a `check` script that runs
/// `svelte-check` (SvelteKit projects run `svelte-kit sync` there first).
#[must_use]
pub fn svelte_check_script(root_dir: &Path) -> bool {
    std::fs::read_to_string(root_dir.join("package.json"))
        .ok()
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
        .and_then(|v| v["scripts"]["check"].as_str().map(str::to_owned))
        .is_some_and(|s| s.contains("svelte-check"))
}

fn show(root_dir: &Path, top: &Path) -> String {
    match root_dir.strip_prefix(top) {
        Ok(r) if r.as_os_str().is_empty() => ".".to_owned(),
        Ok(r) => r.display().to_string(),
        Err(_) => root_dir.display().to_string(),
    }
}

/// R46: why a step of `kind` cannot run in `ctx`, or `None` when its tools
/// are there.
#[must_use]
pub fn missing_tool(kind: StepKind, ctx: &LangCtx<'_>) -> Option<String> {
    let root = show(ctx.root_dir, ctx.top);
    let node = |tool: &str| {
        node_bin(ctx, tool).is_none().then(|| {
            format!(
                "node_modules/.bin/{tool} is missing under {root}: add it to the dev dependencies and run bun install --frozen-lockfile in a [[setup]] step (R45, R46)"
            )
        })
    };
    let bun = || {
        on_path(ctx.path, "bun")
            .is_none()
            .then(|| "bun is not on the job PATH (R46, R52)".to_owned())
    };
    let test_script = || {
        let has = std::fs::read_to_string(ctx.root_dir.join("package.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .is_some_and(|v| v["scripts"]["test"].is_string());
        (!has).then(|| format!("package.json of {root} has no test script for bun run test (R59)"))
    };
    let python = |tool: &str| {
        if on_path(ctx.path, "uv").is_none() {
            return Some("uv is not on the job PATH (R46, R52)".to_owned());
        }
        python_tool(ctx, tool).is_none().then(|| {
            format!(
                "{tool} is not in the .venv of {root} nor on the job PATH: add it to the dev dependencies and run uv sync --frozen in a [[setup]] step (R45, R46)"
            )
        })
    };
    match kind {
        StepKind::Biome => node("biome"),
        StepKind::Tsc => node("tsc"),
        StepKind::SvelteCheck if svelte_check_script(ctx.root_dir) => bun(),
        StepKind::SvelteCheck => node("svelte-check"),
        StepKind::BunTest => bun().or_else(test_script),
        StepKind::Ruff => python("ruff"),
        StepKind::PyrightBaseline => python("pyright"),
        StepKind::PytestBaseline => python("pytest"),
        _ => None,
    }
}

/// Extra environment of a step of `kind`: Python steps write no
/// `__pycache__` into the checkout (R42).
#[must_use]
pub fn step_env(kind: StepKind) -> BTreeMap<String, String> {
    if is_python(kind) {
        [("PYTHONDONTWRITEBYTECODE".to_owned(), "1".to_owned())].into()
    } else {
        BTreeMap::new()
    }
}

/// The `sh` script of the `ruff` step: both checks run, either failure
/// fails the step. `--no-cache`: no `.ruff_cache` in the checkout (R42).
const RUFF_SCRIPT: &str = "rc=0\nuv run --no-sync ruff check --no-cache --force-exclude -- \"$@\" || rc=1\nuv run --no-sync ruff format --check --no-cache --force-exclude -- \"$@\" || rc=1\nexit $rc";

/// The files of `scope` relative to the root that still exist as files, or
/// `None` for the whole root.
fn root_files(scope: &Scope, root_dir: &Path, top: &Path) -> Option<Vec<OsString>> {
    let Scope::Files { files } = scope else {
        return None;
    };
    let rel_root = root_dir.strip_prefix(top).unwrap_or(Path::new(""));
    Some(
        files
            .iter()
            .filter_map(|f| Path::new(f).strip_prefix(rel_root).ok())
            .filter(|f| is_file(&root_dir.join(f)))
            .map(|f| f.as_os_str().to_owned())
            .collect(),
    )
}

/// The command line of a TypeScript or Python step, or `Ok(None)` when a
/// file-scoped step has no file left to lint.
pub fn invocation(
    kind: StepKind,
    scope: &Scope,
    ctx: &LangCtx<'_>,
) -> Result<Option<Invocation>, String> {
    let files = root_files(scope, ctx.root_dir, ctx.top);
    if files.as_ref().is_some_and(Vec::is_empty) {
        return Ok(None);
    }
    let node = |tool: &str| {
        node_bin(ctx, tool).ok_or_else(|| format!("node_modules/.bin/{tool} is missing (R46)"))
    };
    let os = |items: &[&str]| -> Vec<OsString> { items.iter().map(OsString::from).collect() };
    Ok(Some(match kind {
        StepKind::Biome => {
            let mut args = os(&[
                "check",
                "--files-ignore-unknown=true",
                "--no-errors-on-unmatched",
            ]);
            if let Some(f) = files {
                args.push("--".into());
                args.extend(f);
            }
            Invocation {
                program: node("biome")?.into(),
                args,
            }
        }
        StepKind::Tsc => Invocation {
            program: node("tsc")?.into(),
            args: os(&["--noEmit"]),
        },
        StepKind::SvelteCheck if svelte_check_script(ctx.root_dir) => Invocation {
            program: "bun".into(),
            args: os(&["run", "check"]),
        },
        StepKind::SvelteCheck => Invocation {
            program: node("svelte-check")?.into(),
            args: os(&["--output", "human"]),
        },
        StepKind::BunTest => Invocation {
            program: "bun".into(),
            args: os(&["run", "test"]),
        },
        StepKind::Ruff => {
            let mut args = os(&["-c", RUFF_SCRIPT, "ruff"]);
            args.extend(files.unwrap_or_default());
            Invocation {
                program: "sh".into(),
                args,
            }
        }
        StepKind::PyrightBaseline | StepKind::PytestBaseline => {
            let mut args = os(&[
                "__step",
                if kind == StepKind::PyrightBaseline {
                    "pyright-baseline"
                } else {
                    "pytest-baseline"
                },
                "--findings",
            ]);
            args.push(ctx.findings.into());
            args.push("--root".into());
            args.push(show(ctx.root_dir, ctx.top).into());
            if let Some(b) = ctx.baseline {
                args.push("--baseline".into());
                args.push(b.into());
            }
            Invocation {
                program: ctx.tollgate.into(),
                args,
            }
        }
        other => {
            return Err(format!(
                "step kind {} is not a TypeScript or Python kind",
                serde_json::to_string(&other).unwrap_or_default()
            ));
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(p: &[&str]) -> Vec<PathBuf> {
        p.iter().map(PathBuf::from).collect()
    }

    fn set(p: &[&str]) -> BTreeSet<String> {
        p.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn lint_pick_follows_changes_and_configs_r59_r60() {
        let none = BTreeSet::new();
        let dash = Path::new("dashboard");
        let changed = paths(&["dashboard/src/a.ts", "dashboard/README.md", "api/x.rs"]);
        assert_eq!(
            lint_pick(StepKind::Biome, dash, &changed, &none),
            LintPick::Files(set(&["dashboard/README.md", "dashboard/src/a.ts"]))
        );
        assert_eq!(
            lint_pick(StepKind::Biome, Path::new("web"), &changed, &none),
            LintPick::Untouched
        );
        let deleted: BTreeSet<PathBuf> = paths(&["dashboard/src/a.ts"]).into_iter().collect();
        assert_eq!(
            lint_pick(
                StepKind::Biome,
                dash,
                &paths(&["dashboard/src/a.ts"]),
                &deleted
            ),
            LintPick::Nothing,
            "a deleted file cannot be linted"
        );
        for config in ["dashboard/biome.json", "dashboard/sub/package.json"] {
            assert_eq!(
                lint_pick(
                    StepKind::Biome,
                    dash,
                    &paths(&[config, "dashboard/x.ts"]),
                    &none
                ),
                LintPick::Whole,
                "{config}"
            );
        }
        let py = paths(&["tools/a.py", "tools/b.pyi", "tools/notes.md", "tools/c.txt"]);
        assert_eq!(
            lint_pick(StepKind::Ruff, Path::new("tools"), &py, &none),
            LintPick::Files(set(&["tools/a.py", "tools/b.pyi"]))
        );
        assert_eq!(
            lint_pick(
                StepKind::Ruff,
                Path::new("tools"),
                &paths(&["tools/notes.md"]),
                &none
            ),
            LintPick::Nothing
        );
        assert_eq!(
            lint_pick(
                StepKind::Ruff,
                Path::new(""),
                &paths(&["pyproject.toml", "a.py"]),
                &none
            ),
            LintPick::Whole
        );
    }

    #[test]
    fn tools_come_from_the_project_r46() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path();
        let root = top.join("dashboard");
        std::fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        std::fs::create_dir_all(top.join("node_modules/.bin")).unwrap();
        std::fs::write(root.join("node_modules/.bin/tsc"), "").unwrap();
        std::fs::write(top.join("node_modules/.bin/biome"), "").unwrap();
        let ctx = LangCtx {
            root_dir: &root,
            top,
            path: Some(OsStr::new("/nonexistent")),
            tollgate: Path::new("/t"),
            baseline: None,
            findings: Path::new("/f"),
        };
        assert_eq!(missing_tool(StepKind::Tsc, &ctx), None);
        assert_eq!(
            missing_tool(StepKind::Biome, &ctx),
            None,
            "hoisted to a parent inside the checkout"
        );
        let m = missing_tool(StepKind::SvelteCheck, &ctx).unwrap();
        assert!(m.contains("node_modules/.bin/svelte-check is missing under dashboard"));
        assert!(
            missing_tool(StepKind::BunTest, &ctx)
                .unwrap()
                .contains("bun is not on the job PATH")
        );
        assert!(
            missing_tool(StepKind::Ruff, &ctx)
                .unwrap()
                .contains("uv is not on the job PATH")
        );
        // A parent outside the checkout does not count.
        let outside = LangCtx { top: &root, ..ctx };
        assert!(missing_tool(StepKind::Biome, &outside).is_some());
        // bun on the PATH, but no test script to run.
        let bin = top.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("bun"), "").unwrap();
        let with_bun = LangCtx {
            path: Some(bin.as_os_str()),
            ..ctx
        };
        assert!(
            missing_tool(StepKind::BunTest, &with_bun)
                .unwrap()
                .contains("package.json of dashboard has no test script")
        );
        std::fs::write(
            root.join("package.json"),
            r#"{"scripts":{"test":"bun test"}}"#,
        )
        .unwrap();
        assert_eq!(missing_tool(StepKind::BunTest, &with_bun), None);
    }

    #[test]
    fn command_lines_r59_r60() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path();
        let root = top.join("web");
        std::fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        for t in ["biome", "tsc", "svelte-check"] {
            std::fs::write(root.join("node_modules/.bin").join(t), "").unwrap();
        }
        std::fs::write(root.join("src/a.ts"), "").unwrap();
        let ctx = LangCtx {
            root_dir: &root,
            top,
            path: None,
            tollgate: Path::new("/bin/tollgate"),
            baseline: Some(Path::new("/j/pyright.baseline.json")),
            findings: Path::new("/j/pyright.findings.json"),
        };
        let line = |kind, scope: &Scope| {
            invocation(kind, scope, &ctx)
                .unwrap()
                .map(|i| i.display().replace(&top.display().to_string(), "<top>"))
        };
        let files = Scope::Files {
            files: set(&["web/src/a.ts", "web/src/gone.ts"]),
        };
        assert_eq!(
            line(StepKind::Biome, &files).unwrap(),
            "<top>/web/node_modules/.bin/biome check --files-ignore-unknown=true --no-errors-on-unmatched -- src/a.ts"
        );
        assert_eq!(
            line(StepKind::Biome, &Scope::All).unwrap(),
            "<top>/web/node_modules/.bin/biome check --files-ignore-unknown=true --no-errors-on-unmatched"
        );
        let gone = Scope::Files {
            files: set(&["web/src/gone.ts"]),
        };
        assert_eq!(line(StepKind::Biome, &gone), None, "nothing left to lint");
        assert_eq!(
            line(StepKind::Tsc, &Scope::All).unwrap(),
            "<top>/web/node_modules/.bin/tsc --noEmit"
        );
        assert_eq!(
            line(StepKind::SvelteCheck, &Scope::All).unwrap(),
            "<top>/web/node_modules/.bin/svelte-check --output human"
        );
        std::fs::write(
            root.join("package.json"),
            r#"{"scripts":{"check":"svelte-kit sync && svelte-check --tsconfig ./tsconfig.json"}}"#,
        )
        .unwrap();
        assert_eq!(
            line(StepKind::SvelteCheck, &Scope::All).unwrap(),
            "bun run check"
        );
        assert_eq!(
            line(StepKind::BunTest, &Scope::All).unwrap(),
            "bun run test"
        );
        let ruff = line(StepKind::Ruff, &Scope::All).unwrap();
        assert!(ruff.starts_with("sh -c "), "{ruff}");
        assert!(ruff.contains("uv run --no-sync ruff check --no-cache --force-exclude"));
        assert!(ruff.ends_with(" ruff"), "{ruff}");
        assert_eq!(
            line(StepKind::PyrightBaseline, &Scope::All).unwrap(),
            "/bin/tollgate __step pyright-baseline --findings /j/pyright.findings.json --root web --baseline /j/pyright.baseline.json"
        );
        let no_base = LangCtx {
            baseline: None,
            ..ctx
        };
        assert_eq!(
            invocation(StepKind::PytestBaseline, &Scope::All, &no_base)
                .unwrap()
                .unwrap()
                .display(),
            "/bin/tollgate __step pytest-baseline --findings /j/pyright.findings.json --root web"
        );
        assert_eq!(step_env(StepKind::Ruff)["PYTHONDONTWRITEBYTECODE"], "1");
        assert!(step_env(StepKind::Tsc).is_empty());
    }
}
