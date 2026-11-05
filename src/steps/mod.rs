//! Step kinds: which steps run in a job, on what, and their command lines
//! (R54, R58, R61, R63).
//!
//! Built kinds: `cargo-fmt`, `cargo-clippy`, `nextest`, `cargo-doctest` and
//! `command`. The TypeScript and Python kinds (`biome`, `tsc`,
//! `svelte-check`, `bun-test`, `ruff`, `pyright-baseline`,
//! `pytest-baseline`) are in the config schema but not built yet: a job
//! that has to run one ends with verdict `error`, cause `config`.

pub mod junit;
pub mod nextest;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::glob::{self, GlobOpts};
use crate::config::repo::{FastTests, RepoConfig, Step, StepKind};
use crate::config::{Platform, Tier};
use crate::select::{Picked, WorkspaceMap};

/// What one step checks (R80; L16 reuse needs it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// The whole workspace or root.
    All,
    /// Selected Rust members.
    Packages {
        /// Reverse-dependency closure (R57e): what is built and tested.
        affected: BTreeSet<String>,
        /// Marked members: the filterset roots (R58).
        marked: BTreeSet<String>,
    },
}

impl Scope {
    /// True when a result on `self` also checked everything `need` does.
    #[must_use]
    pub fn covers(&self, need: &Scope) -> bool {
        match (self, need) {
            (Self::All, _) => true,
            (Self::Packages { .. }, Self::All) => false,
            (
                Self::Packages {
                    affected: a,
                    marked: m,
                },
                Self::Packages {
                    affected: b,
                    marked: n,
                },
            ) => a.is_superset(b) && m.is_superset(n),
        }
    }
}

/// Run or skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Run on this scope.
    Run(Scope),
    /// Not run, with the reason for the report.
    Skip(String),
}

/// One step of a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStep {
    /// The step from the policy config.
    pub step: Step,
    /// What to do.
    pub decision: Decision,
}

/// True for the Rust kinds.
#[must_use]
pub fn is_rust(kind: StepKind) -> bool {
    matches!(
        kind,
        StepKind::CargoFmt | StepKind::CargoClippy | StepKind::Nextest | StepKind::CargoDoctest
    )
}

/// True for kinds this version can run.
#[must_use]
pub fn is_built(kind: StepKind) -> bool {
    is_rust(kind) || kind == StepKind::Command
}

/// The step's dir relative to the repo root.
#[must_use]
pub fn step_root(step: &Step) -> PathBuf {
    step.cwd.as_deref().map(PathBuf::from).unwrap_or_default()
}

/// Which steps of `config` run in a job of `tier` (R54). `picked` is the
/// fast selection; `None` means selection is disabled (`full`, or an
/// untrusted base, R56): every step runs on everything.
#[must_use]
pub fn plan(
    config: &RepoConfig,
    tier: Tier,
    picked: Option<&Picked>,
    platform: Platform,
) -> Vec<PlannedStep> {
    let broad = GlobOpts {
        case_insensitive: false,
        literal_separator: false,
    };
    config
        .steps
        .iter()
        .filter(|s| s.runs_in(tier))
        .map(|s| {
            let decision = if !s.runs_on(platform) {
                Decision::Skip(format!("only_on {:?}", s.only_on))
            } else if let Some(p) = picked.filter(|_| tier == Tier::Fast) {
                fast_decision(s, p, broad)
            } else {
                Decision::Run(Scope::All)
            };
            PlannedStep {
                step: s.clone(),
                decision,
            }
        })
        .collect()
}

fn fast_decision(s: &Step, p: &Picked, broad: GlobOpts) -> Decision {
    if p.code_paths.is_empty() {
        return Decision::Skip("docs-only change (R61)".into());
    }
    let root = step_root(s);
    if is_rust(s.kind) {
        let Some(rp) = p.rust.iter().find(|r| r.root == root) else {
            return Decision::Run(Scope::All);
        };
        if rp.is_empty() {
            return Decision::Skip("no affected package".into());
        }
        if rp.whole || s.kind == StepKind::CargoFmt {
            return Decision::Run(Scope::All);
        }
        return Decision::Run(Scope::Packages {
            affected: rp.affected.clone(),
            marked: rp.marked.clone(),
        });
    }
    if s.kind == StepKind::Command && !s.when.is_empty() {
        let Ok(when) = glob::compile(&s.when, broad) else {
            return Decision::Run(Scope::All);
        };
        return if p.code_paths.iter().any(|c| when.is_match(c)) {
            Decision::Run(Scope::All)
        } else {
            Decision::Skip("no change matches when".into())
        };
    }
    if s.kind != StepKind::Command && !p.code_paths.iter().any(|c| c.starts_with(&root)) {
        return Decision::Skip("no change under its root".into());
    }
    Decision::Run(Scope::All)
}

/// The Rust workspace roots of the steps that run in `tier` on `platform`.
#[must_use]
pub fn rust_roots(config: &RepoConfig, tier: Tier, platform: Platform) -> BTreeSet<PathBuf> {
    config
        .steps
        .iter()
        .filter(|s| is_rust(s.kind) && s.runs_in(tier) && s.runs_on(platform))
        .map(step_root)
        .collect()
}

/// A fast job's selection: what [`crate::select::pick`] marks, the step
/// plan, and the record selection (R80). Shared by the runner (maps from
/// `cargo metadata`) and the front end (cached maps), so both compute the
/// same selection.
#[derive(Debug, Clone)]
pub struct FastPlan {
    /// Marked and affected packages and roots.
    pub picked: Picked,
    /// The steps.
    pub plan: Vec<PlannedStep>,
    /// The record selection.
    pub selection: crate::cache::record::Selection,
}

/// A package name as a selection records it: `<root>:<name>` outside the
/// repo root (R80).
fn root_name(root: &Path, name: &str) -> String {
    if root.as_os_str().is_empty() {
        name.to_owned()
    } else {
        format!("{}:{name}", root.display())
    }
}

/// Plans a fast job relative to `base` (R55-R58, R61, R80).
pub fn fast_plan(
    config: &RepoConfig,
    base: &crate::gitx::Oid,
    changes: &[crate::select::ChangedPath],
    maps: &std::collections::BTreeMap<PathBuf, Option<WorkspaceMap>>,
    other_roots: &[PathBuf],
    platform: Platform,
) -> Result<FastPlan, String> {
    let rules = crate::select::Rules::new(config)?;
    let roots: Vec<crate::select::RustRoot<'_>> = maps
        .iter()
        .map(|(dir, m)| crate::select::RustRoot {
            dir: dir.as_path(),
            map: m.as_ref(),
        })
        .collect();
    let picked = crate::select::pick(changes, &rules, &roots, other_roots);
    let plan = plan(config, Tier::Fast, Some(&picked), platform);
    let selection =
        crate::cache::record::Selection::Subset(crate::cache::record::SubsetSelection {
            base: base.clone(),
            packages: picked
                .rust
                .iter()
                .flat_map(|rp| rp.affected.iter().map(move |n| root_name(&rp.root, n)))
                .collect(),
            // A whole workspace runs without a filterset: every member is a
            // filterset root (R58).
            marked: picked
                .rust
                .iter()
                .flat_map(|rp| {
                    let marked = if rp.whole { &rp.affected } else { &rp.marked };
                    marked.iter().map(move |n| root_name(&rp.root, n))
                })
                .collect(),
            roots: picked
                .roots
                .iter()
                .map(|r| r.display().to_string())
                .collect(),
            steps: plan
                .iter()
                .filter(|s| matches!(s.decision, Decision::Run(_)))
                .map(|s| s.step.name.clone())
                .collect(),
        });
    Ok(FastPlan {
        picked,
        plan,
        selection,
    })
}

/// A command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Program.
    pub program: OsString,
    /// Arguments.
    pub args: Vec<OsString>,
}

impl Invocation {
    fn cargo<I: IntoIterator<Item = S>, S: Into<OsString>>(args: I) -> Self {
        Self {
            program: "cargo".into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// The command line for logs and reports.
    #[must_use]
    pub fn display(&self) -> String {
        std::iter::once(&self.program)
            .chain(&self.args)
            .map(|a| {
                let s = a.to_string_lossy();
                if s.is_empty() || s.contains([' ', '\'', '"', '|', '&', '(', '!']) {
                    format!("'{}'", s.replace('\'', "'\\''"))
                } else {
                    s.into_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// What command lines need besides the step.
#[derive(Debug, Clone, Copy)]
pub struct InvocationCtx<'a> {
    /// The job tier.
    pub tier: Tier,
    /// `select.fast.tests`.
    pub fast_tests: FastTests,
    /// The policy commit's nextest config copy (R49); an empty file when
    /// the policy commit has none.
    pub nextest_config: &'a Path,
    /// The generated tool config (R72).
    pub tool_config: &'a Path,
    /// The workspace map, when metadata worked.
    pub map: Option<&'a WorkspaceMap>,
}

fn package_args(scope: &Scope, names: Option<&BTreeSet<String>>) -> Vec<OsString> {
    match (scope, names) {
        (Scope::Packages { .. }, Some(names)) => names
            .iter()
            .flat_map(|n| [OsString::from("-p"), OsString::from(n)])
            .collect(),
        _ => vec!["--workspace".into()],
    }
}

/// The command line of a built step kind (R58), or `Ok(None)` when there
/// is nothing to run (doctests with no library target).
pub fn invocation(
    step: &Step,
    scope: &Scope,
    ctx: &InvocationCtx<'_>,
) -> Result<Option<Invocation>, String> {
    let affected = match scope {
        Scope::Packages { affected, .. } => Some(affected),
        Scope::All => None,
    };
    Ok(Some(match step.kind {
        StepKind::CargoFmt => Invocation::cargo(["fmt", "--all", "--check"]),
        StepKind::CargoClippy => {
            let mut args: Vec<OsString> = vec!["clippy".into()];
            args.extend(package_args(scope, affected));
            args.extend(["--all-targets", "--", "-D", "warnings"].map(OsString::from));
            Invocation::cargo(args)
        }
        StepKind::Nextest => {
            let mut args: Vec<OsString> = vec!["nextest".into(), "run".into()];
            args.push("--config-file".into());
            args.push(ctx.nextest_config.into());
            let mut tool = OsString::from("tollgate:");
            tool.push(ctx.tool_config);
            args.push("--tool-config-file".into());
            args.push(tool);
            args.extend(
                [
                    "--profile".into(),
                    nextest::profile(ctx.tier),
                    "--no-fail-fast".into(),
                    "--no-tests".into(),
                    "pass".into(),
                ]
                .map(OsString::from),
            );
            if ctx.tier == Tier::Full {
                args.extend(["--flaky-result", "fail"].map(OsString::from));
            }
            args.extend(package_args(scope, affected));
            if let Scope::Packages { marked, .. } = scope
                && let Some(f) = nextest::filterset(ctx.fast_tests, marked)
            {
                args.push("-E".into());
                args.push(f.into());
            }
            Invocation::cargo(args)
        }
        StepKind::CargoDoctest => {
            let libs = match (affected, ctx.map) {
                (Some(a), Some(m)) => Some(m.with_lib(a)),
                (None, Some(m)) => Some(m.with_lib(&m.all())),
                _ => None,
            };
            if libs.as_ref().is_some_and(BTreeSet::is_empty) {
                return Ok(None);
            }
            let mut args: Vec<OsString> = vec!["test".into(), "--doc".into()];
            args.extend(package_args(scope, libs.as_ref()));
            Invocation::cargo(args)
        }
        StepKind::Command => Invocation {
            program: "sh".into(),
            args: vec![
                "-c".into(),
                step.run.clone().ok_or("kind \"command\" needs run")?.into(),
            ],
        },
        other => {
            return Err(format!(
                "step kind {} is not built in this version",
                serde_json::to_string(&other).unwrap_or_default()
            ));
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::select::rust::tests::map;
    use crate::select::{ChangedPath, Rules, RustRoot, pick};

    fn config(steps: &str) -> RepoConfig {
        RepoConfig::from_toml(&format!("version = 1\n{steps}")).unwrap()
    }

    const STEPS: &str = r#"
[[step]]
name = "fmt"
kind = "cargo-fmt"
[[step]]
name = "clippy"
kind = "cargo-clippy"
[[step]]
name = "tests"
kind = "nextest"
[[step]]
name = "doctests"
kind = "cargo-doctest"
[[step]]
name = "ios"
kind = "command"
run = "true"
when = ["ios/**"]
[[step]]
name = "lint"
kind = "command"
run = "true"
only_on = ["macos"]
[[step]]
name = "full-only"
kind = "command"
run = "true"
tiers = ["full"]
"#;

    fn picked(paths: &[&str]) -> Picked {
        let m = map("", &[("a", "crates/a", &["b"]), ("b", "crates/b", &[])]);
        let changes: Vec<ChangedPath> = paths
            .iter()
            .map(|p| ChangedPath {
                path: PathBuf::from(p),
                status: 'M',
            })
            .collect();
        pick(
            &changes,
            &Rules::new(&RepoConfig::default()).unwrap(),
            &[RustRoot {
                dir: Path::new(""),
                map: Some(&m),
            }],
            &[],
        )
    }

    fn decisions(plan: &[PlannedStep]) -> Vec<(String, String)> {
        plan.iter()
            .map(|p| {
                (
                    p.step.name.clone(),
                    match &p.decision {
                        Decision::Run(Scope::All) => "all".to_owned(),
                        Decision::Run(Scope::Packages { affected, .. }) => {
                            affected.iter().cloned().collect::<Vec<_>>().join(",")
                        }
                        Decision::Skip(_) => "skip".to_owned(),
                    },
                )
            })
            .collect()
    }

    #[test]
    fn fast_plan_follows_the_selection_r54_r58() {
        let c = config(STEPS);
        let p = picked(&["crates/b/src/lib.rs"]);
        let got = decisions(&plan(&c, Tier::Fast, Some(&p), Platform::Linux));
        let want = [
            ("fmt", "all"),
            ("clippy", "a,b"),
            ("tests", "a,b"),
            ("doctests", "a,b"),
            ("ios", "skip"),
            ("lint", "skip"),
        ];
        assert_eq!(
            got,
            want.map(|(a, b)| (a.to_owned(), b.to_owned())).to_vec()
        );
        let docs = picked(&["README.md"]);
        assert!(
            plan(&c, Tier::Fast, Some(&docs), Platform::Linux)
                .iter()
                .all(|p| matches!(p.decision, Decision::Skip(_)))
        );
        let ios = picked(&["ios/App.swift"]);
        let got = decisions(&plan(&c, Tier::Fast, Some(&ios), Platform::Linux));
        assert_eq!(got[4], ("ios".into(), "all".into()));
        assert_eq!(got[1], ("clippy".into(), "all".into()), "unowned path");
    }

    #[test]
    fn full_runs_every_step_on_everything_r54() {
        let c = config(STEPS);
        let got = decisions(&plan(&c, Tier::Full, None, Platform::Macos));
        assert_eq!(got.len(), 7);
        assert!(got.iter().all(|(_, d)| d == "all"), "{got:?}");
    }

    #[test]
    fn command_lines_r58() {
        let c = config(STEPS);
        let m = map("", &[("a", "crates/a", &["b"]), ("b", "crates/b", &[])]);
        let ctx = InvocationCtx {
            tier: Tier::Fast,
            fast_tests: FastTests::RdepsAll,
            nextest_config: Path::new("/j/nextest.toml"),
            tool_config: Path::new("/j/tool.toml"),
            map: Some(&m),
        };
        let scope = Scope::Packages {
            affected: ["a".into(), "b".into()].into(),
            marked: ["b".into()].into(),
        };
        let line =
            |i: usize, s: &Scope| invocation(&c.steps[i], s, &ctx).unwrap().unwrap().display();
        assert_eq!(line(0, &scope), "cargo fmt --all --check");
        assert_eq!(
            line(1, &scope),
            "cargo clippy -p a -p b --all-targets -- -D warnings"
        );
        assert_eq!(
            line(2, &scope),
            "cargo nextest run --config-file /j/nextest.toml --tool-config-file tollgate:/j/tool.toml --profile tollgate-fast --no-fail-fast --no-tests pass -p a -p b -E '(rdeps(=b))'"
        );
        assert_eq!(line(3, &Scope::All), "cargo test --doc --workspace");
        assert_eq!(line(4, &Scope::All), "sh -c true");
        let full = InvocationCtx {
            tier: Tier::Full,
            ..ctx
        };
        let nextest = invocation(&c.steps[2], &Scope::All, &full)
            .unwrap()
            .unwrap()
            .display();
        assert!(
            nextest.ends_with("--profile tollgate-full --no-fail-fast --no-tests pass --flaky-result fail --workspace"),
            "{nextest}"
        );
        let mut biome = c.steps[0].clone();
        biome.kind = StepKind::Biome;
        assert!(
            invocation(&biome, &Scope::All, &ctx)
                .unwrap_err()
                .contains("not built")
        );
    }

    #[test]
    fn doctests_skip_packages_without_a_library() {
        let c = config(STEPS);
        let mut m = map("", &[("bin", "crates/bin", &[])]);
        m.packages.get_mut("bin").unwrap().has_lib = false;
        let ctx = InvocationCtx {
            tier: Tier::Fast,
            fast_tests: FastTests::RdepsAll,
            nextest_config: Path::new("/n"),
            tool_config: Path::new("/t"),
            map: Some(&m),
        };
        assert_eq!(invocation(&c.steps[3], &Scope::All, &ctx).unwrap(), None);
    }

    #[test]
    fn scope_cover_rule_l16() {
        let p = |a: &[&str]| Scope::Packages {
            affected: a.iter().map(|s| (*s).to_owned()).collect(),
            marked: a.iter().map(|s| (*s).to_owned()).collect(),
        };
        assert!(Scope::All.covers(&p(&["a"])));
        assert!(p(&["a", "b"]).covers(&p(&["a"])));
        assert!(!p(&["a"]).covers(&p(&["a", "b"])));
        assert!(!p(&["a"]).covers(&Scope::All));
    }
}
