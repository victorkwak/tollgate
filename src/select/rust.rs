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

/// File names whose blobs shape `cargo metadata` (with cargo's version).
const MAP_INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain",
    "rust-toolchain.toml",
];

fn is_map_input(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| MAP_INPUTS.contains(&n))
        || path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|d| d == ".cargo")
}

/// Fingerprint inputs that shape `cargo metadata` besides the tree: cargo
/// itself, the job environment, the host config and cargo config outside
/// the tree (R74).
const MAP_FINGERPRINT_KEYS: &[&str] = &["cargo", "job-env", "host-config", "cargo-config"];

/// The cache key of the workspace map of `root` in a tree, or `None` when
/// the tree's content does not decide the map: a symlink or a submodule
/// under the root (a symlinked manifest or crate dir changes with its
/// target, a submodule's manifests are not in the tree).
///
/// The key covers the `(path, mode, kind, blob)` of every manifest,
/// lockfile, toolchain file and `.cargo/` file in the tree, and the
/// fingerprint inputs of [`MAP_FINGERPRINT_KEYS`]. Two trees with the same
/// key give the same members, manifest dirs and dependency edges, so a hook
/// (which runs no cargo, R51) can select exactly with a map the runner
/// stored.
#[must_use]
pub fn map_key(
    entries: &[crate::gitx::TreeEntry],
    root: &Path,
    fingerprint: &crate::cache::Fingerprint,
) -> Option<String> {
    let under: Vec<&crate::gitx::TreeEntry> = entries
        .iter()
        .filter(|e| e.path.starts_with(root))
        .collect();
    if under.iter().any(|e| e.kind != "blob" || e.mode == "120000") {
        return None;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"tollgate workspace map 2\0");
    h.update(root.as_os_str().as_encoded_bytes());
    h.update(b"\0");
    for k in MAP_FINGERPRINT_KEYS {
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(fingerprint.get(k).unwrap_or("-").as_bytes());
        h.update(b"\0");
    }
    for e in entries.iter().filter(|e| is_map_input(&e.path)) {
        h.update(e.path.as_os_str().as_encoded_bytes());
        h.update(b"\0");
        h.update(e.mode.as_bytes());
        h.update(b"\0");
        h.update(e.kind.as_bytes());
        h.update(b"\0");
        h.update(e.oid.as_str().as_bytes());
        h.update(b"\0");
    }
    Some(h.finalize().to_hex().to_string())
}

/// A stored map for `key`.
#[must_use]
pub fn load_cached(dirs: &crate::dirs::Dirs, key: &str) -> Option<WorkspaceMap> {
    let bytes = crate::fsx::read_optional(&dirs.workspace_map_file(key))
        .ok()
        .flatten()?;
    serde_json::from_slice(&bytes).ok()
}

/// Stores a map computed by `cargo metadata` in a verify checkout.
pub fn store_cached(
    dirs: &crate::dirs::Dirs,
    key: &str,
    map: &WorkspaceMap,
) -> std::io::Result<()> {
    let json = serde_json::to_vec(map).map_err(std::io::Error::other)?;
    crate::fsx::write_atomic(&dirs.workspace_map_file(key), &json)
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
    fn map_key_tracks_only_manifest_inputs() {
        use crate::cache::Fingerprint;
        use crate::gitx::{Oid, TreeEntry};
        let e = |p: &str, o: char| TreeEntry {
            mode: "100644".into(),
            kind: "blob".into(),
            oid: Oid::parse(&o.to_string().repeat(40)).unwrap(),
            path: PathBuf::from(p),
        };
        let fp = |cargo: &str| {
            let mut f = Fingerprint::new();
            f.insert("cargo", cargo);
            f.insert("job-env", "env");
            f.insert("rustc", "ignored");
            f
        };
        let key = |entries: &[TreeEntry], root: &str, f: &Fingerprint| {
            map_key(entries, Path::new(root), f).unwrap()
        };
        let base = vec![
            e("Cargo.toml", '1'),
            e("Cargo.lock", '2'),
            e("crates/a/Cargo.toml", '3'),
            e("crates/a/src/lib.rs", '4'),
            e("README.md", '5'),
        ];
        let k = key(&base, "", &fp("cargo 1.99"));
        let mut src = base.clone();
        src[3] = e("crates/a/src/lib.rs", '9');
        src[4] = e("README.md", '9');
        assert_eq!(key(&src, "", &fp("cargo 1.99")), k);
        let mut other_rustc = fp("cargo 1.99");
        other_rustc.insert("rustc", "changed");
        assert_eq!(key(&base, "", &other_rustc), k);
        let mut manifest = base.clone();
        manifest[2] = e("crates/a/Cargo.toml", '9');
        assert_ne!(key(&manifest, "", &fp("cargo 1.99")), k);
        let mut config = base.clone();
        config.push(e(".cargo/config.toml", '7'));
        assert_ne!(key(&config, "", &fp("cargo 1.99")), k);
        assert_ne!(key(&base, "", &fp("cargo 2.0")), k);
        assert_ne!(key(&base, "rust", &fp("cargo 1.99")), k);
        let mut env = fp("cargo 1.99");
        env.insert("job-env", "other");
        assert_ne!(key(&base, "", &env), k, "the job env shapes cargo metadata");
        let mut home = fp("cargo 1.99");
        home.insert("cargo-config", "x");
        assert_ne!(key(&base, "", &home), k, "cargo config outside the tree");
        let mut exec = base.clone();
        exec[2].mode = "100755".into();
        assert_ne!(key(&exec, "", &fp("cargo 1.99")), k, "mode counts");
    }

    #[test]
    fn no_map_key_when_symlinks_or_submodules_decide_the_map_r57() {
        use crate::cache::Fingerprint;
        use crate::gitx::{Oid, TreeEntry};
        let e = |p: &str, mode: &str, kind: &str| TreeEntry {
            mode: mode.into(),
            kind: kind.into(),
            oid: Oid::parse(&"1".repeat(40)).unwrap(),
            path: PathBuf::from(p),
        };
        let fp = Fingerprint::new();
        let plain = vec![e("Cargo.toml", "100644", "blob")];
        assert!(map_key(&plain, Path::new(""), &fp).is_some());
        // A symlinked manifest: its target's content is not in the key.
        let mut link = plain.clone();
        link.push(e("crates/b/Cargo.toml", "120000", "blob"));
        assert!(map_key(&link, Path::new(""), &fp).is_none());
        // A symlinked crate dir.
        let mut dir = plain.clone();
        dir.push(e("crates/b", "120000", "blob"));
        assert!(map_key(&dir, Path::new(""), &fp).is_none());
        // A submodule: its manifests are not in the tree.
        let mut sub = plain.clone();
        sub.push(e("vendor/dep", "160000", "commit"));
        assert!(map_key(&sub, Path::new(""), &fp).is_none());
        // Outside a root one level down, they do not matter.
        let mut outside = vec![e("rust/Cargo.toml", "100644", "blob")];
        outside.push(e("docs/link", "120000", "blob"));
        assert!(map_key(&outside, Path::new("rust"), &fp).is_some());
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
