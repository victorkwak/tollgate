//! Cache: fingerprint and toolcache with real shim processes (T36, R75), and
//! the record store rules (T35, T37, R34, R53, R76-R81).

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use support::Sandbox;
use tollgate::cache::fingerprint::{self, FingerprintError, FingerprintInputs, Roots};
use tollgate::cache::record::{
    ErrorCause, Record, Selection, StepResult, StepStatus, SubsetSelection, Verdict,
};
use tollgate::cache::store::{Lookup, LookupRequest, RecordStore, StoreError, WriteOutcome};
use tollgate::cache::toolcache::ToolCache;
use tollgate::cache::{Fingerprint, RECORD_SCHEMA, record_key};
use tollgate::config::Tier;
use tollgate::dirs::Dirs;
use tollgate::gitx::Oid;
use tollgate::ids::{JobId, ResourceName};
use tollgate::runner::env::{EnvFile, JobEnv};

/// A shell-script tool that counts its runs in `<path>.runs`.
fn shim(path: &Path, output: &str) {
    let counter = format!("{}.runs", path.display());
    support::write_exe(
        path,
        &format!("#!/bin/sh\necho x >> '{counter}'\nprintf '%s\\n' '{output}'\n"),
    );
}

fn runs(path: &Path) -> usize {
    std::fs::read_to_string(format!("{}.runs", path.display()))
        .map(|s| s.lines().count())
        .unwrap_or(0)
}

struct Tools {
    bin: PathBuf,
    env: JobEnv,
}

fn tools(sb: &Sandbox) -> Tools {
    let bin = sb.root().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    shim(&bin.join("rustc"), "rustc 1.96.1 (shim)");
    shim(&bin.join("cargo"), "cargo 1.96.1 (shim)");
    shim(&bin.join("cargo-nextest"), "cargo-nextest 0.9.150");
    shim(&bin.join("git"), "git version 2.56.0");
    let env = JobEnv::from_vars([("PATH", bin.as_os_str()), ("HOME", sb.home.as_os_str())]);
    Tools { bin, env }
}

fn compute(t: &Tools, cwd: &Path, cache: &mut ToolCache) -> Fingerprint {
    compute_with(&t.env, cwd, cache, &[], &BTreeMap::new()).unwrap()
}

fn compute_with(
    env: &JobEnv,
    cwd: &Path,
    cache: &mut ToolCache,
    env_files: &[EnvFile],
    images: &BTreeMap<ResourceName, String>,
) -> Result<Fingerprint, FingerprintError> {
    fingerprint::compute(
        &FingerprintInputs {
            roots: Roots {
                rust: true,
                typescript: true,
                python: false,
            },
            job_env: env,
            cwd,
            host_config_hash: "h",
            effective_config_hash: "e",
            env_files,
            images,
        },
        cache,
    )
}

fn tree(n: u8) -> Oid {
    Oid::parse(&format!("{n:02x}").repeat(20)).unwrap()
}

#[test]
fn fingerprint_inputs_and_toolcache_hits_r74_r75_t36() {
    let sb = Sandbox::new();
    let t = tools(&sb);
    let cache_file = sb.root().join("state/toolcache.json");
    let mut cache = ToolCache::load(&cache_file);
    let fp = compute(&t, &sb.root(), &mut cache);
    assert_eq!(fp.get("rustc"), Some("rustc 1.96.1 (shim)"));
    assert_eq!(fp.get("cargo-nextest"), Some("cargo-nextest 0.9.150"));
    assert_eq!(fp.get("bun"), Some("absent"));
    assert_eq!(fp.get("uv"), None, "no Python root, no uv probe");
    assert_eq!(fp.get("tollgate"), Some(tollgate::VERSION));
    assert!(fp.get("uname").is_some() && fp.get("job-env").is_some());
    assert_eq!(cache.stats().runs, 4);
    cache.save().unwrap();

    // R75: a fresh process (new cache from disk) runs no tool.
    let mut cache = ToolCache::load(&cache_file);
    let again = compute(&t, &sb.root(), &mut cache);
    assert_eq!(again, fp);
    assert_eq!(cache.stats().runs, 0);
    assert_eq!(runs(&t.bin.join("rustc")), 1);

    // T36: a new rustc gives a new fingerprint and key.
    shim(&t.bin.join("rustc"), "rustc 1.97.0 (shim)");
    let newer = compute(&t, &sb.root(), &mut cache);
    assert_ne!(newer.get("rustc"), fp.get("rustc"));
    assert_ne!(
        record_key(&tree(1), Tier::Fast, &newer),
        record_key(&tree(1), Tier::Fast, &fp)
    );

    // T36: an mtime change alone invalidates the cache entry (re-probe).
    let before = runs(&t.bin.join("rustc"));
    // Read-only fd: a write fd could make a concurrent exec fail (ETXTBSY).
    let f = std::fs::File::open(t.bin.join("rustc")).unwrap();
    f.set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(5))
        .unwrap();
    let same = compute(&t, &sb.root(), &mut cache);
    assert_eq!(runs(&t.bin.join("rustc")), before + 1);
    assert_eq!(same, newer);

    // T36: another job env entry gives another key.
    let env2 = JobEnv::from_vars([
        ("PATH", t.bin.as_os_str()),
        ("HOME", sb.home.as_os_str()),
        ("SQLX_OFFLINE", "true".as_ref()),
    ]);
    let other = compute_with(&env2, &sb.root(), &mut cache, &[], &BTreeMap::new()).unwrap();
    assert_ne!(other.get("job-env"), same.get("job-env"));
}

#[test]
fn env_files_and_images_r74() {
    let sb = Sandbox::new();
    let t = tools(&sb);
    let mut cache = ToolCache::load(&sb.root().join("tc.json"));
    let env_file_path = sb.root().join("secrets.env");
    std::fs::write(&env_file_path, "A=1\n").unwrap();
    let ef = EnvFile::read(&env_file_path).unwrap();
    let pg = ResourceName::parse("pg").unwrap();
    let images: BTreeMap<_, _> = [(pg, "postgres:16".to_owned())].into();

    // No docker on the job PATH: R34 cause docker.
    let err = compute_with(
        &t.env,
        &sb.root(),
        &mut cache,
        std::slice::from_ref(&ef),
        &images,
    )
    .unwrap_err();
    assert!(matches!(err, FingerprintError::Docker { .. }), "{err}");

    shim(&t.bin.join("docker"), "sha256:1111");
    let fp = compute_with(
        &t.env,
        &sb.root(),
        &mut cache,
        std::slice::from_ref(&ef),
        &images,
    )
    .unwrap();
    assert_eq!(fp.get("image:pg"), Some("sha256:1111"));
    assert_eq!(
        fp.get(&format!("env-file:{}", env_file_path.display())),
        Some(ef.hash.as_str())
    );
    // A re-pulled image changes the fingerprint (no caching of image ids).
    shim(&t.bin.join("docker"), "sha256:2222");
    let fp2 = compute_with(&t.env, &sb.root(), &mut cache, &[ef], &images).unwrap();
    assert_ne!(fp, fp2);
}

struct Store {
    dirs: Dirs,
    store: RecordStore,
    fp: Fingerprint,
}

fn store(sb: &Sandbox) -> Store {
    let dirs = Dirs::from_env(&sb.env()).unwrap();
    let mut fp = Fingerprint::new();
    fp.insert("rustc", "rustc 1.96.1");
    Store {
        store: RecordStore::new(&dirs),
        dirs,
        fp,
    }
}

fn subset(packages: &[&str]) -> Selection {
    Selection::Subset(SubsetSelection {
        base: tree(9),
        packages: packages.iter().map(|s| (*s).to_owned()).collect(),
        roots: BTreeSet::new(),
        steps: ["clippy".to_owned(), "tests".to_owned()].into(),
    })
}

impl Store {
    /// A record with its job report written first, as the runner does.
    fn record(&self, tree: &Oid, tier: Tier, verdict: Verdict, selection: Selection) -> Record {
        let now = jiff::Timestamp::now();
        let job = JobId::generate(now);
        tollgate::fsx::write_atomic(&self.dirs.job_report(&job), b"{}").unwrap();
        Record {
            schema: RECORD_SCHEMA,
            key: record_key(tree, tier, &self.fp),
            tree: tree.clone(),
            tier,
            verdict,
            verdict_class: verdict.class(),
            cause: (verdict == Verdict::Error).then_some(ErrorCause::Setup),
            ttl_secs: None,
            fingerprint: self.fp.clone(),
            policy_commit: None,
            base_tree: None,
            selection,
            started: now,
            finished: now,
            duration_ms: 1200,
            host: "test".into(),
            tollgate_version: tollgate::VERSION.into(),
            job_id: job,
            steps: vec![StepResult {
                name: "tests".into(),
                status: StepStatus::Pass,
                duration_ms: 1000,
                exit: Some(0),
                log: Some("tests.log".into()),
                failing: vec![],
            }],
            flaky: vec![],
            quarantine_hits: vec![],
        }
    }

    fn lookup(&self, tree: &Oid, tier: Tier, needed: &Selection) -> Lookup {
        self.lookup_at(tree, tier, needed, jiff::Timestamp::now())
    }

    fn lookup_at(
        &self,
        tree: &Oid,
        tier: Tier,
        needed: &Selection,
        now: jiff::Timestamp,
    ) -> Lookup {
        self.store
            .lookup(&LookupRequest {
                tree,
                tier,
                fingerprint: &self.fp,
                needed,
                now,
            })
            .unwrap()
    }
}

#[test]
fn full_pass_satisfies_both_tiers_and_fast_never_full_r53_r78() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(1);
    let fast = s.record(&t, Tier::Fast, Verdict::Pass, Selection::All);
    assert_eq!(s.store.write(&fast).unwrap(), WriteOutcome::Written);
    assert!(matches!(
        s.lookup(&t, Tier::Fast, &subset(&["a"])),
        Lookup::Pass(_)
    ));
    assert_eq!(s.lookup(&t, Tier::Full, &Selection::All), Lookup::Miss);

    let full = s.record(&t, Tier::Full, Verdict::Pass, Selection::All);
    s.store.write(&full).unwrap();
    assert_eq!(
        s.lookup(&t, Tier::Full, &Selection::All),
        Lookup::Pass(full.clone())
    );
    assert_eq!(
        s.lookup(&t, Tier::Fast, &Selection::All),
        Lookup::Pass(full)
    );
    // Record file path and no temp files (R76).
    let dir = s.dirs.record_file(&fast.key).parent().unwrap().to_owned();
    for e in std::fs::read_dir(dir).unwrap() {
        let name = e.unwrap().file_name().into_string().unwrap();
        assert!(name.ends_with(".json") && !name.starts_with('.'), "{name}");
    }
}

#[test]
fn missing_report_invalidates_a_pass_r81_t37() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(2);
    let full = s.record(&t, Tier::Full, Verdict::Pass, Selection::All);
    s.store.write(&full).unwrap();
    std::fs::remove_file(s.dirs.job_report(&full.job_id)).unwrap();
    assert_eq!(s.lookup(&t, Tier::Full, &Selection::All), Lookup::Miss);
}

#[test]
fn fast_selection_superset_rule_r79_r80_t35() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(3);
    let one = s.record(&t, Tier::Fast, Verdict::Pass, subset(&["a"]));
    s.store.write(&one).unwrap();
    assert!(matches!(
        s.lookup(&t, Tier::Fast, &subset(&["a"])),
        Lookup::Pass(_)
    ));
    assert_eq!(s.lookup(&t, Tier::Fast, &subset(&["a", "b"])), Lookup::Miss);
    assert_eq!(s.lookup(&t, Tier::Fast, &Selection::All), Lookup::Miss);

    let two = s.record(&t, Tier::Fast, Verdict::Pass, subset(&["a", "b"]));
    assert_eq!(s.store.write(&two).unwrap(), WriteOutcome::Written);
    // A narrower pass does not replace a broader one.
    let narrow = s.record(&t, Tier::Fast, Verdict::Pass, subset(&["b"]));
    assert_eq!(s.store.write(&narrow).unwrap(), WriteOutcome::KeptBroader);
    assert_eq!(
        s.lookup(&t, Tier::Fast, &subset(&["a", "b"])),
        Lookup::Pass(two)
    );

    let all = s.record(&t, Tier::Fast, Verdict::Pass, Selection::All);
    s.store.write(&all).unwrap();
    assert!(matches!(
        s.lookup(&t, Tier::Fast, &Selection::All),
        Lookup::Pass(_)
    ));
}

#[test]
fn fail_is_cached_until_removed_r34() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(4);
    let fail = s.record(&t, Tier::Fast, Verdict::Fail, subset(&["a"]));
    s.store.write(&fail).unwrap();
    // The failing checks are part of a bigger selection: deny.
    assert_eq!(
        s.lookup(&t, Tier::Fast, &subset(&["a", "b"])),
        Lookup::Fail(fail.clone())
    );
    // A selection without them runs.
    assert_eq!(s.lookup(&t, Tier::Fast, &subset(&["b"])), Lookup::Miss);
    // A full fail denies full, not fast.
    let full_fail = s.record(&t, Tier::Full, Verdict::Fail, Selection::All);
    s.store.write(&full_fail).unwrap();
    assert_eq!(
        s.lookup(&t, Tier::Full, &Selection::All),
        Lookup::Fail(full_fail.clone())
    );
    assert_eq!(s.lookup(&t, Tier::Fast, &subset(&["b"])), Lookup::Miss);
    // `check --rerun` removes it.
    assert!(s.store.remove(&full_fail.key).unwrap());
    assert!(!s.store.remove(&full_fail.key).unwrap());
    assert_eq!(s.lookup(&t, Tier::Full, &Selection::All), Lookup::Miss);
}

#[test]
fn environmental_verdicts_expire_r34() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(5);
    let timeout = s.record(&t, Tier::Full, Verdict::Timeout, Selection::All);
    s.store.write(&timeout).unwrap();
    let now = timeout.finished;
    assert!(matches!(
        s.lookup_at(&t, Tier::Full, &Selection::All, now),
        Lookup::Environmental(_)
    ));
    let later = now + jiff::SignedDuration::from_mins(16);
    assert_eq!(
        s.lookup_at(&t, Tier::Full, &Selection::All, later),
        Lookup::Miss
    );

    let error = s.record(&t, Tier::Fast, Verdict::Error, Selection::All);
    s.store.write(&error).unwrap();
    assert!(matches!(
        s.lookup_at(&t, Tier::Fast, &Selection::All, error.finished),
        Lookup::Environmental(_)
    ));
}

#[test]
fn store_refuses_records_that_break_the_rules() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(6);
    let mut deferred = s.record(&t, Tier::Fast, Verdict::Error, Selection::All);
    deferred.cause = Some(ErrorCause::Deferred);
    assert!(matches!(
        s.store.write(&deferred),
        Err(StoreError::Invalid(_))
    ));

    let mut no_cause = s.record(&t, Tier::Fast, Verdict::Error, Selection::All);
    no_cause.cause = None;
    assert!(s.store.write(&no_cause).is_err());

    let mut wrong_key = s.record(&t, Tier::Fast, Verdict::Pass, Selection::All);
    wrong_key.tree = tree(7);
    assert!(s.store.write(&wrong_key).is_err());

    let full_subset = s.record(&t, Tier::Full, Verdict::Pass, subset(&["a"]));
    assert!(s.store.write(&full_subset).is_err());

    let no_report = s.record(&t, Tier::Fast, Verdict::Pass, Selection::All);
    std::fs::remove_file(s.dirs.job_report(&no_report.job_id)).unwrap();
    assert!(s.store.write(&no_report).is_err());
}

#[test]
fn corrupt_records_are_misses_and_list_skips_them() {
    let sb = Sandbox::new();
    let s = store(&sb);
    let t = tree(8);
    let good = s.record(&t, Tier::Full, Verdict::Pass, Selection::All);
    s.store.write(&good).unwrap();
    let bad_key = record_key(&t, Tier::Fast, &s.fp);
    tollgate::fsx::write_atomic(&s.dirs.record_file(&bad_key), b"{not json").unwrap();
    assert!(matches!(
        s.store.read(&bad_key),
        Err(StoreError::Corrupt { .. })
    ));
    // The full pass still answers; the corrupt fast file is ignored.
    assert!(matches!(
        s.lookup(&t, Tier::Fast, &Selection::All),
        Lookup::Pass(_)
    ));
    let listed = s.store.list().unwrap();
    assert_eq!(listed, vec![good]);
}

#[test]
fn step_key_tracks_only_the_step_inputs_l16() {
    use tollgate::cache::step::{step_inputs, step_key};
    use tollgate::config::RepoConfig;
    use tollgate::gitx::Git;

    let sb = Sandbox::new();
    let repo = sb.repo("r");
    sb.commit_file(&repo, "crates/a/src/lib.rs", "pub fn a() {}\n", "a");
    sb.commit_file(&repo, "ios/App/main.swift", "print(1)\n", "ios");
    sb.commit_file(&repo, "docs/x y é.md", "x\n", "docs");
    let git = Git::scrubbed(&sb.env(), &repo);
    let entries = || {
        let tree = git.tree_of("HEAD").unwrap().unwrap();
        git.ls_tree(&tree).unwrap()
    };
    let e0 = entries();
    assert_eq!(e0.len(), 4, "{e0:?}");
    assert!(
        e0.iter().any(|e| e.path == Path::new("docs/x y é.md")
            && e.mode == "100644"
            && e.kind == "blob")
    );

    let cfg = RepoConfig::from_toml(
        r#"version = 1
[[step]]
name = "tests"
kind = "nextest"
inputs = ["crates/**", "Cargo.*"]
[[step]]
name = "ios"
kind = "command"
run = "swiftlint"
inputs = ["ios/**"]
[[step]]
name = "fmt"
kind = "cargo-fmt"
exclude_inputs = ["docs/**"]
"#,
    )
    .unwrap();
    let mut fp = Fingerprint::new();
    fp.insert("rustc", "rustc 1.96.1");
    let keys = |entries: &[tollgate::gitx::TreeEntry], fp: &Fingerprint| {
        cfg.steps
            .iter()
            .map(|s| step_key(s, fp, entries).unwrap())
            .collect::<Vec<_>>()
    };
    let k0 = keys(&e0, &fp);
    assert_eq!(
        step_inputs(&cfg.steps[0], &e0).unwrap().len(),
        1,
        "only crates/a/src/lib.rs"
    );

    // An iOS-only change keeps the Rust step key (no rerun of the suite).
    sb.commit_file(&repo, "ios/App/main.swift", "print(2)\n", "ios2");
    let k1 = keys(&entries(), &fp);
    assert_eq!(k0[0], k1[0]);
    assert_ne!(k0[1], k1[1]);
    assert_ne!(k0[2], k1[2]);

    // An excluded docs change changes no key.
    sb.commit_file(&repo, "docs/x y é.md", "y\n", "docs2");
    assert_eq!(keys(&entries(), &fp), k1);

    // A mode change of an input changes its step key.
    sb.git(
        &repo,
        &["update-index", "--chmod=+x", "crates/a/src/lib.rs"],
    );
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "chmod"]);
    let k3 = keys(&entries(), &fp);
    assert_ne!(k1[0], k3[0]);
    assert_eq!(k1[1], k3[1]);

    // The step definition and the fingerprint are part of the key.
    let mut changed = cfg.steps[0].clone();
    changed.env.insert("RUST_LOG".into(), "debug".into());
    assert_ne!(step_key(&changed, &fp, &entries()).unwrap(), k3[0]);
    let mut fp2 = fp.clone();
    fp2.insert("rustc", "rustc 1.97.0");
    assert_ne!(keys(&entries(), &fp2)[0], k3[0]);
}
