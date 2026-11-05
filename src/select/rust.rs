//! Rust workspace map from `cargo metadata` (R57, L6).
//!
//! L6: `cargo_metadata` only, no guppy. The reverse-dependency closure is
//! computed from the resolve graph and includes normal, build and dev
//! dependency edges between workspace members, so a change in `b` also
//! selects `a` when `a` only dev-depends on `b`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One workspace member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Manifest dir relative to the repo root (`""` for the repo root).
    pub manifest_dir: PathBuf,
    /// Has a library or proc-macro target (doctests run, R58).
    pub has_lib: bool,
    /// Members that depend on this one through any edge kind.
    pub dependents: BTreeSet<String>,
}

/// The members of one Cargo workspace and their reverse dependencies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMap {
    /// Workspace root dir relative to the repo root.
    pub root: PathBuf,
    /// Members by name.
    pub packages: BTreeMap<String, PackageInfo>,
    /// Absolute target dir (nextest store, JUnit file).
    pub target_dir: PathBuf,
}

fn rel(path: &Path, repo_root: &Path) -> Result<PathBuf, String> {
    path.strip_prefix(repo_root)
        .map(Path::to_owned)
        .map_err(|_| {
            format!(
                "{} is outside the checkout {}",
                path.display(),
                repo_root.display()
            )
        })
}

impl WorkspaceMap {
    /// Builds the map from `cargo metadata` JSON. `repo_root` is the
    /// canonical checkout root; `root` the workspace dir relative to it.
    pub fn from_metadata_json(json: &str, repo_root: &Path, root: &Path) -> Result<Self, String> {
        let meta = cargo_metadata::MetadataCommand::parse(json)
            .map_err(|e| format!("cargo metadata output: {e}"))?;
        let members: BTreeSet<&cargo_metadata::PackageId> = meta.workspace_members.iter().collect();
        let mut names: BTreeMap<&cargo_metadata::PackageId, String> = BTreeMap::new();
        let mut packages = BTreeMap::new();
        for p in meta.packages.iter().filter(|p| members.contains(&p.id)) {
            let dir = p
                .manifest_path
                .parent()
                .ok_or_else(|| format!("manifest {} has no parent", p.manifest_path))?;
            let name = p.name.to_string();
            names.insert(&p.id, name.clone());
            packages.insert(
                name,
                PackageInfo {
                    manifest_dir: rel(dir.as_std_path(), repo_root)?,
                    has_lib: p.targets.iter().any(|t| t.is_lib() || t.is_proc_macro()),
                    dependents: BTreeSet::new(),
                },
            );
        }
        let resolve = meta
            .resolve
            .as_ref()
            .ok_or("cargo metadata has no resolve graph")?;
        for node in &resolve.nodes {
            let Some(dependent) = names.get(&node.id) else {
                continue;
            };
            for dep in &node.deps {
                if let Some(dep_name) = names.get(&dep.pkg)
                    && dep_name != dependent
                    && let Some(info) = packages.get_mut(dep_name)
                {
                    info.dependents.insert(dependent.clone());
                }
            }
        }
        Ok(Self {
            root: root.to_owned(),
            packages,
            target_dir: meta.target_directory.into_std_path_buf(),
        })
    }

    /// The member whose manifest dir is the longest prefix of `path`
    /// (R57c).
    #[must_use]
    pub fn package_for(&self, path: &Path) -> Option<&str> {
        self.packages
            .iter()
            .filter(|(_, p)| path.starts_with(&p.manifest_dir))
            .max_by_key(|(_, p)| p.manifest_dir.components().count())
            .map(|(n, _)| n.as_str())
    }

    /// Every member name.
    #[must_use]
    pub fn all(&self) -> BTreeSet<String> {
        self.packages.keys().cloned().collect()
    }

    /// The reverse-dependency closure of `marked`, `marked` included
    /// (R57e). Names that are not members are ignored.
    #[must_use]
    pub fn closure(&self, marked: &BTreeSet<String>) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<&str> = marked
            .iter()
            .filter(|n| self.packages.contains_key(*n))
            .map(String::as_str)
            .collect();
        while let Some(n) = stack.pop() {
            if !out.insert(n.to_owned()) {
                continue;
            }
            if let Some(p) = self.packages.get(n) {
                stack.extend(p.dependents.iter().map(String::as_str));
            }
        }
        out
    }

    /// Members of `names` with a library target (doctests, R58).
    #[must_use]
    pub fn with_lib(&self, names: &BTreeSet<String>) -> BTreeSet<String> {
        names
            .iter()
            .filter(|n| self.packages.get(*n).is_some_and(|p| p.has_lib))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A map without cargo: `(name, dir, dependencies)`.
    pub(crate) fn map(root: &str, members: &[(&str, &str, &[&str])]) -> WorkspaceMap {
        let mut packages: BTreeMap<String, PackageInfo> = members
            .iter()
            .map(|(n, d, _)| {
                (
                    (*n).to_owned(),
                    PackageInfo {
                        manifest_dir: PathBuf::from(d),
                        has_lib: true,
                        dependents: BTreeSet::new(),
                    },
                )
            })
            .collect();
        for (n, _, deps) in members {
            for d in *deps {
                packages
                    .get_mut(*d)
                    .unwrap()
                    .dependents
                    .insert((*n).to_owned());
            }
        }
        WorkspaceMap {
            root: PathBuf::from(root),
            packages,
            target_dir: PathBuf::from("/t"),
        }
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn closure_follows_reverse_edges_r57e() {
        // a dev-depends on b; c depends on a; d stands alone.
        let m = map(
            "",
            &[
                ("a", "crates/a", &["b"]),
                ("b", "crates/b", &[]),
                ("c", "crates/c", &["a"]),
                ("d", "crates/d", &[]),
            ],
        );
        assert_eq!(m.closure(&set(&["b"])), set(&["a", "b", "c"]));
        assert_eq!(m.closure(&set(&["a"])), set(&["a", "c"]));
        assert_eq!(m.closure(&set(&["d", "zzz"])), set(&["d"]));
    }

    #[test]
    fn longest_manifest_prefix_wins_r57c() {
        let m = map("", &[("root", "", &[]), ("inner", "crates/inner", &[])]);
        assert_eq!(
            m.package_for(Path::new("crates/inner/src/lib.rs")),
            Some("inner")
        );
        assert_eq!(m.package_for(Path::new("src/main.rs")), Some("root"));
        let n = map("", &[("x", "crates/x", &[])]);
        assert_eq!(n.package_for(Path::new("crates/xy/src/lib.rs")), None);
    }
}
