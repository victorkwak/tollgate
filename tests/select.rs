//! T30, T31 (R55-R58, L6): selection on a real Cargo workspace with real
//! `cargo metadata`, `git diff-tree` and `cargo nextest list`.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::{Sandbox, Scratch};
use tollgate::config::RepoConfig;
use tollgate::config::repo::FastTests;
use tollgate::gitx::{Git, Oid};
use tollgate::select::{self, Rules, RustRoot, WorkspaceMap};
use tollgate::steps::nextest;

/// cargo from the system toolchain with the sandbox HOME, as jobs run it.
fn cargo(sb: &Sandbox, dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("cargo")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &sb.home)
        .env("CARGO_TARGET_DIR", dir.join("target"))
        .output()
        .unwrap()
}

fn workspace_map(sb: &Sandbox, repo: &Path) -> WorkspaceMap {
    let out = cargo(sb, repo, &["metadata", "--format-version", "1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    WorkspaceMap::from_metadata_json(&String::from_utf8(out.stdout).unwrap(), repo, Path::new(""))
        .unwrap()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_owned()).collect()
}

#[test]
fn metadata_closure_and_diff_tree_select_dev_dependents_t30() {
    let sb = Sandbox::new();
    let repo = sb.rust_repo("ws", Scratch::default());
    let map = workspace_map(&sb, &repo);
    assert_eq!(map.all(), set(&["a", "b"]));
    assert_eq!(
        map.packages["b"].dependents,
        set(&["a"]),
        "dev-dependency edge (L6)"
    );
    assert_eq!(map.packages["a"].manifest_dir, PathBuf::from("crates/a"));
    assert!(map.target_dir.ends_with("target"));

    let git = Git::scrubbed(&sb.env(), &repo);
    let base = git.tree_of("HEAD").unwrap().unwrap();
    support::write_b(&repo, 2);
    std::fs::write(repo.join("crates/b/src/extra.rs"), "").unwrap();
    std::fs::remove_file(repo.join("crates/b/tests/it.rs")).unwrap();
    sb.git(&repo, &["add", "-A"]);
    let tree = git.write_tree().unwrap();
    let changes = select::changed_paths(&git, &base, &tree).unwrap();
    let mut paths: Vec<_> = changes
        .iter()
        .map(|c| (c.status, c.path.display().to_string()))
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [
            ('A', "crates/b/src/extra.rs".to_owned()),
            ('D', "crates/b/tests/it.rs".to_owned()),
        ]
    );
    let rules = Rules::new(&RepoConfig::default()).unwrap();
    let picked = select::pick(
        &changes,
        &rules,
        &[RustRoot {
            dir: Path::new(""),
            map: Some(&map),
        }],
        &[],
    );
    assert_eq!(picked.rust[0].marked, set(&["b"]));
    assert_eq!(picked.rust[0].affected, set(&["a", "b"]));

    // Same base and tree: an empty diff.
    let empty = Oid::parse(&tree.to_string()).unwrap();
    assert!(
        select::changed_paths(&git, &tree, &empty)
            .unwrap()
            .is_empty()
    );
}

fn listed(sb: &Sandbox, repo: &Path, filter: &str) -> BTreeSet<String> {
    let out = cargo(
        sb,
        repo,
        &[
            "nextest",
            "list",
            "--message-format",
            "json",
            "--workspace",
            "-E",
            filter,
        ],
    );
    assert!(
        out.status.success(),
        "{filter}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let mut tests = BTreeSet::new();
    for (bin, suite) in v["rust-suites"].as_object().unwrap() {
        for (name, case) in suite["testcases"].as_object().unwrap() {
            if case["filter-match"]["status"] == "matches" {
                tests.insert(format!("{bin} {name}"));
            }
        }
    }
    tests
}

#[test]
fn filtersets_select_with_nextest_list_t31() {
    let sb = Sandbox::new();
    let repo = sb.rust_repo("ws", Scratch::default());
    let all = nextest::filterset(FastTests::RdepsAll, &set(&["b"])).unwrap();
    assert_eq!(
        listed(&sb, &repo, &all),
        set(&[
            "a tests::flaky",
            "a tests::ok",
            "b tests::fails",
            "b::it integration"
        ])
    );
    let unit = nextest::filterset(FastTests::RdepsUnitChangedIntegration, &set(&["b"])).unwrap();
    assert_eq!(
        listed(&sb, &repo, &unit),
        set(&[
            "a tests::flaky",
            "a tests::ok",
            "b tests::fails",
            "b::it integration"
        ])
    );
    let only_a = nextest::filterset(FastTests::RdepsUnitChangedIntegration, &set(&["a"])).unwrap();
    assert_eq!(
        listed(&sb, &repo, &only_a),
        set(&["a tests::flaky", "a tests::ok"])
    );
    let pg = nextest::pg_filter(&["b::*".into()]).unwrap();
    assert_eq!(
        listed(&sb, &repo, &pg),
        set(&["b tests::fails", "b::it integration"])
    );
}

#[test]
fn doctests_cover_every_library_crate_type_cargo_documents_r58() {
    let sb = Sandbox::new();
    let repo = sb.root().join("libs");
    let lib = |name: &str, types: &str| {
        let dir = repo.join(name);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("Cargo.toml"),
            format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n[lib]\ncrate-type = [{types}]\n"),
        )
        .unwrap();
        std::fs::write(dir.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
    };
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(
        repo.join("Cargo.toml"),
        "[workspace]\nmembers = [\"both\", \"rlib\", \"dy\", \"c\"]\nresolver = \"2\"\n",
    )
    .unwrap();
    lib("both", "\"cdylib\", \"rlib\"");
    lib("rlib", "\"rlib\"");
    lib("dy", "\"dylib\"");
    lib("c", "\"cdylib\"");
    let map = workspace_map(&sb, &repo);
    assert_eq!(map.with_lib(&map.all()), set(&["both", "rlib"]));
}
