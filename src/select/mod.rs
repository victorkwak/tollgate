//! Changed paths and package selection (R55-R62, L6).
//!
//! [`pick`] maps each changed path of a `fast` job to what it affects:
//!
//! 1. Docs-only paths (R61) affect nothing.
//! 2. Rust global triggers (R57a) and `select.global` mark a whole
//!    workspace.
//! 3. `select.owners` globs mark their packages (R57b); an owner that is not
//!    a member marks every workspace and warns.
//! 4. A path under a member's manifest dir marks that member (R57c).
//! 5. A path under a TypeScript or Python root belongs to that root.
//! 6. Anything else marks the whole workspace that contains it, or every
//!    workspace when none does (R57d). Deletions count.
//!
//! The affected set is the reverse-dependency closure of the marked members
//! (R57e). A workspace without a map (metadata failed) is always whole
//! (R58).

pub mod detect;
pub mod rust;

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use globset::GlobSet;

use crate::config::RepoConfig;
use crate::config::glob::{self, GlobOpts};
use crate::gitx::{Git, GitError, Oid};
use crate::policy::PolicyMatcher;

pub use rust::WorkspaceMap;

/// One line of `git diff-tree --name-status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedPath {
    /// Repo-relative path.
    pub path: PathBuf,
    /// `A`, `D`, `M`, `T`.
    pub status: char,
}

/// R55: `git diff-tree -r -z --no-renames --name-status <base> <tree>`.
/// Renames show as a deletion and an addition, so both paths count.
pub fn changed_paths(git: &Git, base: &Oid, tree: &Oid) -> Result<Vec<ChangedPath>, GitError> {
    let out = git.run([
        "diff-tree",
        "-r",
        "-z",
        "--no-renames",
        "--name-status",
        base.as_str(),
        tree.as_str(),
    ])?;
    let mut fields = out.split(|b| *b == 0).filter(|f| !f.is_empty());
    let mut changes = Vec::new();
    while let (Some(status), Some(path)) = (fields.next(), fields.next()) {
        changes.push(ChangedPath {
            path: PathBuf::from(OsStr::from_bytes(path)),
            status: status.first().map_or('?', |b| char::from(*b)),
        });
    }
    Ok(changes)
}

/// Built-in docs extensions (R61).
const DOCS_EXTENSIONS: &[&str] = &[
    "md", "mdx", "rst", "txt", "png", "jpg", "jpeg", "gif", "svg", "webp",
];

/// R61: built-in docs files are never docs-only under these.
const NOT_DOCS_DIRS: &[&str] = &[
    "**/tests/**",
    "**/fixtures/**",
    "**/src/**",
    "prompts/**",
    "migrations/**",
];

/// Compiled selection rules from the policy config.
#[derive(Debug, Clone)]
pub struct Rules {
    global: GlobSet,
    owners: Vec<(GlobSet, Vec<String>)>,
    docs_only: GlobSet,
    not_docs: GlobSet,
    policy: PolicyMatcher,
}

const BROAD: GlobOpts = GlobOpts {
    case_insensitive: false,
    literal_separator: false,
};
const NARROW: GlobOpts = GlobOpts {
    case_insensitive: false,
    literal_separator: true,
};

impl Rules {
    /// Compiles the rules of `config`. `select.global` and `owners` match
    /// broadly (`*` crosses `/`: they mark more); `select.docs_only` matches
    /// narrowly (`*` stops at `/`: it exempts only what it names).
    pub fn new(config: &RepoConfig) -> Result<Self, String> {
        Ok(Self {
            global: glob::compile(&config.select.global, BROAD)?,
            owners: config
                .select
                .owners
                .iter()
                .map(|(g, pkgs)| Ok((glob::compile(&[g], BROAD)?, pkgs.clone())))
                .collect::<Result<_, String>>()?,
            docs_only: glob::compile(&config.select.docs_only, NARROW)?,
            not_docs: glob::compile(NOT_DOCS_DIRS, NARROW)?,
            policy: PolicyMatcher::new(config)?,
        })
    }

    /// The policy files matcher (R71).
    #[must_use]
    pub fn policy(&self) -> &PolicyMatcher {
        &self.policy
    }

    fn owned(&self, path: &Path) -> bool {
        self.owners.iter().any(|(g, _)| g.is_match(path))
    }

    /// R61: true when `path` cannot affect any check.
    #[must_use]
    pub fn docs_only(&self, path: &Path, code_roots: &[PathBuf]) -> bool {
        if self.policy.is_policy_file(path) {
            return false;
        }
        if self.docs_only.is_match(path) {
            return true;
        }
        let docs_ext = path
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|e| DOCS_EXTENSIONS.contains(&e.to_ascii_lowercase().as_str()));
        docs_ext
            && !code_roots.iter().any(|r| path.starts_with(r))
            && !self.global.is_match(path)
            && !self.owned(path)
            && !self.not_docs.is_match(path)
    }
}

/// One Rust workspace as selection sees it.
#[derive(Debug, Clone, Copy)]
pub struct RustRoot<'a> {
    /// Workspace dir relative to the repo root.
    pub dir: &'a Path,
    /// Its members; `None` when metadata failed (always whole, R58).
    pub map: Option<&'a WorkspaceMap>,
}

/// What a fast job needs in one Rust workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustPick {
    /// Workspace dir.
    pub root: PathBuf,
    /// The whole workspace is marked.
    pub whole: bool,
    /// Marked members (R57).
    pub marked: BTreeSet<String>,
    /// What is built: their reverse-dependency closure, or every member
    /// when `whole` or when the query cache changed (R57f).
    pub affected: BTreeSet<String>,
}

impl RustPick {
    /// True when nothing in this workspace needs checking.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self.whole && self.affected.is_empty()
    }
}

/// The result of [`pick`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Picked {
    /// Changed paths that are not docs-only.
    pub code_paths: Vec<PathBuf>,
    /// The code paths that were deleted (a linter cannot check them).
    pub deleted: BTreeSet<PathBuf>,
    /// Per Rust workspace, in input order.
    pub rust: Vec<RustPick>,
    /// TypeScript/Python roots with changes.
    pub roots: BTreeSet<PathBuf>,
    /// `WARN` lines (R57b).
    pub warnings: Vec<String>,
}

impl Picked {
    /// R61: every changed path is docs-only (and there is at least one).
    #[must_use]
    pub fn docs_only(&self, changes: &[ChangedPath]) -> bool {
        !changes.is_empty() && self.code_paths.is_empty()
    }
}

/// Global triggers of one Rust workspace (R57a).
fn rust_global(path: &Path, root: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(root) else {
        return path == Path::new("tollgate.toml");
    };
    if path == Path::new("tollgate.toml") {
        return true;
    }
    let name = rel.file_name().and_then(OsStr::to_str).unwrap_or("");
    let first = rel.components().next().map(|c| c.as_os_str());
    matches!(
        rel.to_str(),
        Some(
            "Cargo.toml"
                | "Cargo.lock"
                | "rust-toolchain"
                | "rust-toolchain.toml"
                | ".config/nextest.toml"
        )
    ) || first == Some(OsStr::new(".cargo"))
        || matches!(
            name,
            "clippy.toml" | ".clippy.toml" | "rustfmt.toml" | ".rustfmt.toml" | "build.rs"
        )
}

/// The `sqlx` offline query cache of one Rust workspace (R57f). A macro of
/// any member can read it at compile time, and nothing reads it at run time.
fn query_cache(path: &Path, root: &Path) -> bool {
    path.strip_prefix(root).is_ok_and(|rel| {
        rel.components().next().map(|c| c.as_os_str()) == Some(OsStr::new(".sqlx"))
    })
}

/// Maps the changes of a `fast` job to affected packages and roots (R57).
#[must_use]
pub fn pick(
    changes: &[ChangedPath],
    rules: &Rules,
    rust: &[RustRoot<'_>],
    other_roots: &[PathBuf],
) -> Picked {
    let mut code_roots: Vec<PathBuf> = other_roots.to_vec();
    for r in rust {
        match r.map {
            Some(m) => code_roots.extend(m.packages.values().map(|p| p.manifest_dir.clone())),
            None => code_roots.push(r.dir.to_owned()),
        }
    }
    let mut out = Picked::default();
    let mut whole = vec![false; rust.len()];
    let mut build_all = vec![false; rust.len()];
    let mut marked: Vec<BTreeSet<String>> = vec![BTreeSet::new(); rust.len()];
    let mut unknown_owner = BTreeSet::new();
    for c in changes {
        let p = c.path.as_path();
        if rules.docs_only(p, &code_roots) {
            continue;
        }
        out.code_paths.push(p.to_owned());
        if c.status == 'D' {
            out.deleted.insert(p.to_owned());
        }
        if rules.global.is_match(p) {
            whole.iter_mut().for_each(|w| *w = true);
            continue;
        }
        let mut matched = false;
        for (i, r) in rust.iter().enumerate() {
            if rust_global(p, r.dir) {
                whole[i] = true;
                matched = true;
            } else if query_cache(p, r.dir) {
                build_all[i] = true;
                matched = true;
            }
        }
        for (g, pkgs) in &rules.owners {
            if !g.is_match(p) {
                continue;
            }
            matched = true;
            for pkg in pkgs {
                let mut found = false;
                for (i, r) in rust.iter().enumerate() {
                    if r.map.is_some_and(|m| m.packages.contains_key(pkg)) {
                        marked[i].insert(pkg.clone());
                        found = true;
                    }
                }
                if !found {
                    unknown_owner.insert(pkg.clone());
                }
            }
        }
        for (i, r) in rust.iter().enumerate() {
            // R57f: the query cache belongs to no member, also when the
            // workspace root is a package.
            if query_cache(p, r.dir) {
                continue;
            }
            if let Some(pkg) = r.map.and_then(|m| m.package_for(p)) {
                marked[i].insert(pkg.to_owned());
                matched = true;
            }
        }
        if matched {
            continue;
        }
        if let Some(root) = other_roots
            .iter()
            .filter(|r| p.starts_with(r))
            .max_by_key(|r| r.components().count())
        {
            out.roots.insert(root.clone());
            continue;
        }
        let containing: Vec<usize> = rust
            .iter()
            .enumerate()
            .filter(|(_, r)| p.starts_with(r.dir))
            .map(|(i, _)| i)
            .collect();
        if containing.is_empty() {
            whole.iter_mut().for_each(|w| *w = true);
        } else {
            for i in containing {
                whole[i] = true;
            }
        }
    }
    if !unknown_owner.is_empty() {
        whole.iter_mut().for_each(|w| *w = true);
        for name in &unknown_owner {
            out.warnings.push(format!(
                "WARN owners: unknown package {name}; selecting the whole workspace"
            ));
        }
    }
    for (i, r) in rust.iter().enumerate() {
        // R57f: a query cache change with no marked member does not say
        // which tests to run, so every test runs.
        let whole = whole[i] || r.map.is_none() || (build_all[i] && marked[i].is_empty());
        let affected = match r.map {
            Some(m) if whole || build_all[i] => m.all(),
            Some(m) => m.closure(&marked[i]),
            None => BTreeSet::new(),
        };
        out.rust.push(RustPick {
            root: r.dir.to_owned(),
            whole,
            marked: std::mem::take(&mut marked[i]),
            affected,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::select::rust::tests::map;

    fn changes(paths: &[&str]) -> Vec<ChangedPath> {
        paths
            .iter()
            .map(|p| ChangedPath {
                path: PathBuf::from(p),
                status: 'M',
            })
            .collect()
    }

    fn config(text: &str) -> RepoConfig {
        RepoConfig::from_toml(&format!("version = 1\n{text}")).unwrap()
    }

    fn ws() -> WorkspaceMap {
        // a dev-depends on b.
        map("", &[("a", "crates/a", &["b"]), ("b", "crates/b", &[])])
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    fn run(cfg: &RepoConfig, paths: &[&str], other: &[&str]) -> Picked {
        let m = ws();
        let rules = Rules::new(cfg).unwrap();
        let other: Vec<PathBuf> = other.iter().map(PathBuf::from).collect();
        pick(
            &changes(paths),
            &rules,
            &[RustRoot {
                dir: Path::new(""),
                map: Some(&m),
            }],
            &other,
        )
    }

    #[test]
    fn query_cache_builds_everything_and_tests_the_marked_r57f() {
        let c = RepoConfig::default();
        // With a marked member: every member is built, `a` alone is a
        // filterset root.
        let p = run(&c, &[".sqlx/query-1.json", "crates/a/src/lib.rs"], &[]);
        assert!(!p.rust[0].whole);
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        assert_eq!(p.rust[0].marked, set(&["a"]));
        // The order of the paths does not matter, and a deletion counts.
        let mut ch = changes(&["crates/a/src/lib.rs", ".sqlx/query-1.json"]);
        ch[1].status = 'D';
        let m = ws();
        let roots = [RustRoot {
            dir: Path::new(""),
            map: Some(&m),
        }];
        let p = pick(&ch, &Rules::new(&c).unwrap(), &roots, &[]);
        assert!(!p.rust[0].whole);
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        assert_eq!(p.rust[0].marked, set(&["a"]));
        // An owner entry marks too.
        let owned = config("[select.owners]\n\"migrations/**\" = [\"a\"]\n");
        let p = run(&owned, &[".sqlx/query-1.json", "migrations/1.sql"], &[]);
        assert!(!p.rust[0].whole);
        assert_eq!(p.rust[0].marked, set(&["a"]));
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        // No marked member: nothing says which tests to run, so all run.
        let p = run(&c, &[".sqlx/query-1.json"], &[]);
        assert!(p.rust[0].whole);
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        let p = run(&c, &[".sqlx/query-1.json", "docs/x.md"], &[]);
        assert!(p.rust[0].whole);
        // A global trigger in the same change still wins.
        let p = run(
            &c,
            &[".sqlx/query-1.json", "crates/a/src/lib.rs", "Cargo.lock"],
            &[],
        );
        assert!(p.rust[0].whole);
        // `select.global` restores the whole-workspace rule.
        let global = config("[select]\nglobal = [\".sqlx/**\"]\n");
        let p = run(&global, &[".sqlx/query-1.json", "crates/a/src/lib.rs"], &[]);
        assert!(p.rust[0].whole);
        // Only the query cache of the workspace counts.
        let m = map(
            "svc",
            &[("a", "svc/crates/a", &["b"]), ("b", "svc/crates/b", &[])],
        );
        let roots = [RustRoot {
            dir: Path::new("svc"),
            map: Some(&m),
        }];
        let p = pick(
            &changes(&["svc/.sqlx/query-1.json", "svc/crates/a/src/lib.rs"]),
            &Rules::new(&c).unwrap(),
            &roots,
            &[],
        );
        assert!(!p.rust[0].whole);
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        assert_eq!(p.rust[0].marked, set(&["a"]));
        // A root package does not own the query cache: alone, the change
        // still runs every test, and with `a` it does not mark `app`.
        let m = map(
            "",
            &[
                ("app", "", &[]),
                ("a", "crates/a", &["b"]),
                ("b", "crates/b", &[]),
            ],
        );
        let roots = [RustRoot {
            dir: Path::new(""),
            map: Some(&m),
        }];
        let rules = Rules::new(&c).unwrap();
        let p = pick(&changes(&[".sqlx/query-1.json"]), &rules, &roots, &[]);
        assert!(p.rust[0].whole);
        let p = pick(
            &changes(&[".sqlx/query-1.json", "crates/a/src/lib.rs"]),
            &rules,
            &roots,
            &[],
        );
        assert!(!p.rust[0].whole);
        assert_eq!(p.rust[0].marked, set(&["a"]));
        assert_eq!(p.rust[0].affected, set(&["a", "app", "b"]));
        // A second workspace with no change of its own is not touched.
        let n = map("svc", &[("s", "svc/crates/s", &[])]);
        let two = [
            roots[0],
            RustRoot {
                dir: Path::new("svc"),
                map: Some(&n),
            },
        ];
        let p = pick(
            &changes(&[".sqlx/query-1.json", "crates/a/src/lib.rs"]),
            &rules,
            &two,
            &[],
        );
        assert!(p.rust[1].is_empty());
    }

    #[test]
    fn crate_change_selects_its_reverse_deps_incl_dev_t30() {
        let c = RepoConfig::default();
        let p = run(&c, &["crates/b/src/lib.rs"], &[]);
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        assert!(!p.rust[0].whole);
        let p = run(&c, &["crates/a/src/lib.rs"], &[]);
        assert_eq!(p.rust[0].affected, set(&["a"]));
    }

    #[test]
    fn global_triggers_and_unowned_paths_select_everything_r57() {
        let c = RepoConfig::default();
        for path in [
            "Cargo.lock",
            "Cargo.toml",
            ".cargo/config.toml",
            "rust-toolchain.toml",
            "crates/a/build.rs",
            "tollgate.toml",
            ".config/nextest.toml",
            "clippy.toml",
            "scripts/run.sh",
            "crates/c/src/lib.rs",
        ] {
            let p = run(&c, &[path], &[]);
            assert!(p.rust[0].whole, "{path}");
            assert_eq!(p.rust[0].affected, set(&["a", "b"]), "{path}");
        }
        // Deletions count (T30).
        let mut del = changes(&["crates/gone/src/lib.rs"]);
        del[0].status = 'D';
        let m = ws();
        let p = pick(
            &del,
            &Rules::new(&c).unwrap(),
            &[RustRoot {
                dir: Path::new(""),
                map: Some(&m),
            }],
            &[],
        );
        assert!(p.rust[0].whole);
    }

    #[test]
    fn owners_and_unknown_owners_r57b() {
        let c = config("[select.owners]\n\"migrations/**\" = [\"b\"]\n");
        let p = run(&c, &["migrations/001.sql"], &[]);
        assert_eq!(p.rust[0].affected, set(&["a", "b"]));
        assert!(!p.rust[0].whole);
        let c = config("[select.owners]\n\"migrations/**\" = [\"gatehouse-core\"]\n");
        let p = run(&c, &["migrations/001.sql"], &[]);
        assert!(p.rust[0].whole);
        assert!(
            p.warnings[0].contains("unknown package gatehouse-core"),
            "{:?}",
            p.warnings
        );
    }

    #[test]
    fn docs_only_rules_r61_t32() {
        let c = config("[select]\nglobal = [\"prompts/**\"]\n");
        let rules = Rules::new(&c).unwrap();
        let roots = vec![PathBuf::from("crates/a"), PathBuf::from("dashboard")];
        let docs = |p: &str| rules.docs_only(Path::new(p), &roots);
        assert!(docs("README.md"));
        assert!(docs("docs/guide/intro.MD"));
        assert!(docs("img/logo.png"));
        assert!(!docs("tests/fixtures/sum.png"), "T32 fixture");
        assert!(!docs("crates/a/README.md"), "inside a package");
        assert!(!docs("dashboard/notes.md"), "inside a TS root");
        assert!(!docs("prompts/guard.md"), "select.global");
        assert!(!docs("migrations/README.md"));
        assert!(!docs("src/notes.txt"));
        assert!(!docs("main.rs"));
        let opt_in = Rules::new(&config(
            "[select]\ndocs_only = [\"*.md\", \"docs/**\"]\n[policy]\nfiles = [\"rules.md\"]\n",
        ))
        .unwrap();
        assert!(opt_in.docs_only(Path::new("docs/a.rs"), &roots));
        assert!(
            !opt_in.docs_only(Path::new("crates/a/x.rs"), &roots),
            "* stops at /"
        );
        assert!(
            !opt_in.docs_only(Path::new("rules.md"), &roots),
            "policy files are never docs-only (R71)"
        );
        assert!(!opt_in.docs_only(Path::new("tollgate.toml"), &roots));
    }

    #[test]
    fn docs_only_job_and_other_roots() {
        let c = RepoConfig::default();
        let p = run(&c, &["README.md"], &[]);
        assert!(p.docs_only(&changes(&["README.md"])));
        assert!(p.rust[0].is_empty());
        assert!(
            !Picked::default().docs_only(&[]),
            "an empty diff is not docs-only (R56)"
        );
        let p = run(&c, &["dashboard/src/x.ts"], &["dashboard"]);
        assert_eq!(p.roots, [PathBuf::from("dashboard")].into());
        assert!(p.rust[0].is_empty());
    }

    #[test]
    fn missing_metadata_is_whole_r58() {
        let rules = Rules::new(&RepoConfig::default()).unwrap();
        let p = pick(
            &changes(&["README.md", "x/y.rs"]),
            &rules,
            &[RustRoot {
                dir: Path::new(""),
                map: None,
            }],
            &[],
        );
        assert!(p.rust[0].whole);
        assert_eq!(
            p.code_paths.len(),
            2,
            "README under the root is not docs-only"
        );
    }
}
