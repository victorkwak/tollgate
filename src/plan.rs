//! The front end of a check: plan a job, look up its record, start or
//! attach to the job, wait (R15, R32, R34, R53, R56, R74, R78-R81, R88,
//! R89, L2, L16).
//!
//! Used by `tollgate check` now and by the gate hooks later, through
//! [`plan`], [`lookup`], [`start`] and [`settle`] (never [`wait`] alone on
//! an attached job: its selection may differ, R79, R88). It runs only
//! `git` (R51) and tool version probes that the tool cache usually answers
//! (R75): no `cargo`. The exact selection a `fast` lookup needs comes from
//! workspace maps the runner cached for the tree's manifests; without them
//! [`Needed::SameBase`] accepts a record of the same base tree, and the
//! runner re-checks with the exact selection.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::cache::fingerprint::{self, FingerprintError, FingerprintInputs, Roots};
use crate::cache::record::{Needed, Selection, Verdict};
use crate::cache::store::{Lookup, LookupRequest, RecordStore, StoreError};
use crate::cache::toolcache::ToolCache;
use crate::cache::{Fingerprint, record_key};
use crate::config::host::JobConfig;
use crate::config::repo::StepKind;
use crate::config::{CompiledScope, LoadedHost, Platform, Tier};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::gitx::{Git, GitError, Oid, RepoLayout};
use crate::ids::{JobId, ResourceName};
use crate::locks::Priority;
use crate::policy::{self, PolicyError};
use crate::remote_refs::{RemoteRefs, TrustedRemote};
use crate::report::JobReport;
use crate::runner::env::{BaseInputs, EnvFile, JobEnv};
use crate::runner::job::{JobSpec, PolicySpec, SPEC_SCHEMA};
use crate::runner::spawn;
use crate::sched::{self, Claim, JobMeta, JobState, JobStore, Origin};
use crate::{select, steps};

/// Error while planning or starting a job.
#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    /// git.
    #[error(transparent)]
    Git(#[from] GitError),
    /// Policy or config (R64).
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Config or environment.
    #[error("{0}")]
    Config(String),
    /// Fingerprint (docker errors write no record, R34).
    #[error(transparent)]
    Fingerprint(#[from] FingerprintError),
    /// Record store.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Job store or files.
    #[error("{0}")]
    Io(String),
}

/// The base of a `fast` selection (R55).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// Base tree.
    pub tree: Oid,
    /// Base commit, for the reachability trust rule (R56).
    pub commit: Option<Oid>,
}

/// What to check.
#[derive(Debug)]
pub struct PlanRequest<'a> {
    /// tollgate's environment.
    pub env: &'a EnvSnapshot,
    /// Dirs.
    pub dirs: &'a Dirs,
    /// Host config.
    pub host: &'a LoadedHost,
    /// The repo.
    pub layout: &'a RepoLayout,
    /// Scrubbed git in the repo (R52).
    pub git: &'a Git,
    /// The tree (R40).
    pub tree: Oid,
    /// Tier.
    pub tier: Tier,
    /// The new commit `N` whose policy applies (L2); `None` on an unborn
    /// branch.
    pub tip: Option<Oid>,
    /// Selection base; `None` disables selection.
    pub base: Option<Base>,
    /// Origin ref (R89).
    pub refname: String,
    /// L16 reuse wanted (CI sets false). It applies to `fast` jobs and to
    /// `full` jobs of non-full refs only.
    pub allow_reuse: bool,
    /// Queue rank (R89).
    pub priority: Priority,
    /// `check --rerun`.
    pub rerun: bool,
}

/// A planned job.
#[derive(Debug, Clone)]
pub struct Plan {
    /// The spec the runner gets.
    pub spec: JobSpec,
    /// What a lookup needs (R79).
    pub needed: Needed,
    /// L16: a `full` check of a full ref (or with reuse turned off) accepts
    /// only a `full` pass whose steps all ran fresh.
    pub fresh_only: bool,
}

/// rustup's toolchain files.
const TOOLCHAIN_FILES: &[&str] = &["rust-toolchain", "rust-toolchain.toml"];

/// The toolchain files that apply to Rust root `root` in the tree: those of
/// the nearest dir from `root` up to the repo root that has any (rustup
/// searches from the step's dir upward).
fn toolchain_files<'a>(
    entries: &'a [crate::gitx::TreeEntry],
    root: &Path,
) -> Vec<&'a crate::gitx::TreeEntry> {
    let mut dir = Some(root);
    while let Some(d) = dir {
        let found: Vec<&crate::gitx::TreeEntry> = entries
            .iter()
            .filter(|e| e.kind == "blob" && TOOLCHAIN_FILES.iter().any(|f| e.path == d.join(f)))
            .collect();
        if !found.is_empty() {
            return found;
        }
        dir = if d.as_os_str().is_empty() {
            None
        } else {
            Some(d.parent().unwrap_or(Path::new("")))
        };
    }
    Vec::new()
}

/// How many symlinks a toolchain file may go through inside the tree.
const MAX_TOOLCHAIN_LINKS: usize = 8;

/// The content of toolchain file `e` as a regular file (R51): a symlink is
/// followed only to a file of the same tree. Returns the blob id and its
/// bytes.
fn toolchain_blob(
    git: &Git,
    entries: &[crate::gitx::TreeEntry],
    e: &crate::gitx::TreeEntry,
) -> Result<(Oid, Vec<u8>), PlanError> {
    let refuse = |why: String| {
        PlanError::Config(format!(
            "{}: {why}; the hook runs no tool the tree chooses (R51)",
            e.path.display()
        ))
    };
    let mut cur = e.clone();
    for _ in 0..=MAX_TOOLCHAIN_LINKS {
        match cur.mode.as_str() {
            "100644" | "100755" => {
                let bytes = git.run(["cat-file", "blob", cur.oid.as_str()])?;
                return Ok((cur.oid.clone(), bytes));
            }
            "120000" => {
                let target = git.run(["cat-file", "blob", cur.oid.as_str()])?;
                let target = PathBuf::from(std::ffi::OsString::from(
                    String::from_utf8_lossy(&target).into_owned(),
                ));
                let mut path = cur.path.parent().map(Path::to_owned).unwrap_or_default();
                for c in target.components() {
                    match c {
                        std::path::Component::Normal(n) => path.push(n),
                        std::path::Component::CurDir => {}
                        std::path::Component::ParentDir if path.pop() => {}
                        _ => {
                            return Err(refuse(format!(
                                "a symlink to {}, which is not a file of the same tree",
                                target.display()
                            )));
                        }
                    }
                }
                cur = entries
                    .iter()
                    .find(|x| x.path == path && x.kind == "blob")
                    .cloned()
                    .ok_or_else(|| {
                        refuse(format!(
                            "a symlink to {}, which is not a file of the same tree",
                            target.display()
                        ))
                    })?;
            }
            mode => return Err(refuse(format!("mode {mode} is not a file"))),
        }
    }
    Err(refuse("too many symlinks".into()))
}

/// R51: a toolchain file that names a toolchain dir (`[toolchain] path`,
/// or a legacy `rust-toolchain` line with a path) would make the version
/// probe run `<path>/bin/rustc`, a binary the tree chooses, in the hook.
fn toolchain_path(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    if let Ok(v) = text.parse::<toml::Table>()
        && let Some(t) = v.get("toolchain").and_then(toml::Value::as_table)
    {
        return t.get("path").map(|p| p.as_str().unwrap_or("?").to_owned());
    }
    let line = text.trim();
    (!line.contains('\n') && (line.contains('/') || line.contains('\\'))).then(|| line.to_owned())
}

/// A dir under the state dir holding `files` under their file names,
/// content-addressed and made once (R51, R74): version probes run there,
/// so rustup picks the toolchain the tree names, not one from the agent's
/// working tree (dirty, untracked or another branch's), and no tool runs in
/// the agent's checkout. The dir holds regular files only: a symlinked
/// toolchain file is written as the file it names in `entries` (the same
/// tree), and one that names a toolchain dir is refused, so the probe never
/// runs a tool the tree chooses (R51).
fn probe_dir(
    dirs: &Dirs,
    git: &Git,
    files: &[&crate::gitx::TreeEntry],
    entries: &[crate::gitx::TreeEntry],
) -> Result<PathBuf, PlanError> {
    let mut blobs = Vec::new();
    for e in files {
        let (oid, bytes) = toolchain_blob(git, entries, e)?;
        if let Some(p) = toolchain_path(&bytes) {
            return Err(PlanError::Config(format!(
                "{}: names the toolchain path {p}; the hook runs no tool the tree chooses (R51), so use a channel",
                e.path.display()
            )));
        }
        blobs.push((
            e.path.file_name().unwrap_or_default().to_owned(),
            oid,
            bytes,
        ));
    }
    let mut h = blake3::Hasher::new();
    h.update(b"tollgate probe dir 2\0");
    for (name, oid, _) in &blobs {
        h.update(name.as_encoded_bytes());
        h.update(b"\0");
        h.update(oid.as_str().as_bytes());
        h.update(b"\0");
    }
    let root = dirs.probe_root();
    let dir = root.join(&h.finalize().to_hex()[..32]);
    if dir.is_dir() {
        return Ok(dir);
    }
    let io = |e: std::io::Error| PlanError::Io(format!("{}: {e}", root.display()));
    let tmp = root.join(format!(".tmp-{}", crate::fsx::unique_suffix()));
    std::fs::create_dir_all(&tmp).map_err(io)?;
    for (name, _, bytes) in &blobs {
        std::fs::write(tmp.join(name), bytes).map_err(io)?;
    }
    match std::fs::rename(&tmp, &dir) {
        Ok(()) => Ok(dir),
        Err(_) if dir.is_dir() => {
            let _ = std::fs::remove_dir_all(&tmp);
            Ok(dir)
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&tmp);
            Err(io(e))
        }
    }
}

/// Probe dirs per group of Rust roots with the same toolchain files (R74):
/// the first group (the first root in order) gives the plain fingerprint
/// keys, each other group `<key>@<root>`.
fn rust_probe_dirs(
    dirs: &Dirs,
    git: &Git,
    entries: &[crate::gitx::TreeEntry],
    roots: &std::collections::BTreeSet<PathBuf>,
) -> Result<Vec<(String, PathBuf)>, PlanError> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for root in roots {
        let dir = probe_dir(dirs, git, &toolchain_files(entries, root), entries)?;
        if out.iter().any(|(_, d)| *d == dir) {
            continue;
        }
        let suffix = if out.is_empty() {
            String::new()
        } else {
            format!("@{}", root.display())
        };
        out.push((suffix, dir));
    }
    Ok(out)
}

/// Root kinds whose tools go into the fingerprint (R74): those of the
/// steps that run, and those detected in `T` (a `command` step can run
/// `cargo` too).
fn kinds_roots(
    spec_config: &crate::config::RepoConfig,
    tier: Tier,
    detected: &select::detect::Roots,
) -> Roots {
    let mut r = Roots {
        rust: !detected.rust.is_empty(),
        typescript: !detected.typescript.is_empty(),
        python: !detected.python.is_empty(),
    };
    for s in spec_config.steps.iter().filter(|s| s.runs_in(tier)) {
        match s.kind {
            StepKind::CargoFmt
            | StepKind::CargoClippy
            | StepKind::Nextest
            | StepKind::CargoDoctest => {
                r.rust = true;
            }
            StepKind::Biome | StepKind::Tsc | StepKind::SvelteCheck | StepKind::BunTest => {
                r.typescript = true;
            }
            StepKind::Ruff | StepKind::PyrightBaseline | StepKind::PytestBaseline => {
                r.python = true;
            }
            StepKind::Command => {}
        }
    }
    r
}

/// One remote's URLs: as configured, and as git uses them after
/// `url.<base>.insteadOf` and `pushInsteadOf` rewrites.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteUrls {
    /// Remote name.
    pub name: String,
    /// `remote.<name>.url` and `remote.<name>.pushurl` values.
    pub configured: Vec<String>,
    /// The URLs `fetch` and `ls-remote` use, in order (git uses the
    /// first).
    pub fetch: Vec<String>,
    /// The URLs `push` uses.
    pub push: Vec<String>,
}

impl RemoteUrls {
    /// Every URL of the remote: configured and as git uses them.
    pub fn all(&self) -> impl Iterator<Item = &String> {
        self.configured.iter().chain(&self.fetch).chain(&self.push)
    }
}

/// True when `url` holds a control character (a newline or tab can fake
/// lines in git's text output).
fn has_control(url: &str) -> bool {
    url.chars().any(char::is_control)
}

/// `git remote get-url [--push] --all <name>`: the URLs after rewrites, one
/// per line. Configured URLs hold no newline (checked first), and a
/// rewrite base is a config subsection name, which holds none either.
fn get_urls(git: &Git, name: &str, push: bool) -> Result<Vec<String>, GitError> {
    let mut args = vec!["remote", "get-url"];
    if push {
        args.push("--push");
    }
    args.extend(["--all", "--", name]);
    let out = git.run(&args)?;
    Ok(String::from_utf8_lossy(&out)
        .split('\n')
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Every remote's URLs: the config values (`git config -z`, NUL-separated)
/// and the URLs git uses for them (`git remote get-url --all`, which
/// applies the rewrites). Never the text of `git remote -v`, whose lines a
/// URL with a newline can fake (R14, L2). A URL with a control character
/// is an error.
pub fn remote_urls(git: &Git) -> Result<Vec<RemoteUrls>, PlanError> {
    let mut remotes: Vec<RemoteUrls> = Vec::new();
    fn entry<'r>(remotes: &'r mut Vec<RemoteUrls>, name: &str) -> &'r mut RemoteUrls {
        if let Some(i) = remotes.iter().position(|r| r.name == name) {
            return &mut remotes[i];
        }
        remotes.push(RemoteUrls {
            name: name.to_owned(),
            ..RemoteUrls::default()
        });
        remotes.last_mut().expect("just pushed")
    }
    // Records are `<key>\n<value>\0`; keys hold no newline.
    let out = git.output([
        "config",
        "-z",
        "--get-regexp",
        r"^remote\..*\.(url|pushurl)$",
    ])?;
    for rec in out.stdout.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let text = String::from_utf8_lossy(rec);
        let Some((key, url)) = text.split_once('\n') else {
            continue;
        };
        let Some(name) = key.strip_prefix("remote.").and_then(|k| {
            k.strip_suffix(".url")
                .or_else(|| k.strip_suffix(".pushurl"))
        }) else {
            continue;
        };
        entry(&mut remotes, name).configured.push(url.to_owned());
    }
    // Remote names are config subsection names: no newline.
    let out = git.run(["remote"])?;
    for name in String::from_utf8_lossy(&out)
        .split('\n')
        .filter(|n| !n.is_empty())
    {
        entry(&mut remotes, name);
    }
    for r in &mut remotes {
        if let Some(u) = r.configured.iter().find(|u| has_control(u)) {
            return Err(PlanError::Config(format!(
                "remote {}: its URL {u:?} holds a control character; fix it with: git remote set-url {} <url>",
                r.name, r.name
            )));
        }
        r.fetch = get_urls(git, &r.name, false)?;
        r.push = get_urls(git, &r.name, true)?;
        if let Some(u) = r.fetch.iter().chain(&r.push).find(|u| has_control(u)) {
            return Err(PlanError::Config(format!(
                "remote {}: git uses the URL {u:?}, which holds a control character (a url.<base>.insteadOf rewrite); remove the rewrite",
                r.name
            )));
        }
    }
    Ok(remotes)
}

/// Which remotes `scope.remotes` trusts (R5, R14, R20, L2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteTrust {
    /// Remotes whose fetch URL, as git uses it, is trusted: their
    /// remote-tracking refs (L2 anchors, R56) and `ls-remote` answers
    /// (R14(2)) come from the trusted server, once it confirms them
    /// ([`RemoteRefs`]).
    pub trusted: Vec<String>,
    /// The same remotes with that fetch URL.
    pub trusted_urls: Vec<TrustedRemote>,
    /// Remotes with any trusted URL, configured or as git uses it: a push
    /// to one is a push to a trusted remote (R5, R20), wherever a
    /// `pushInsteadOf` sends it.
    pub push_trusted: Vec<String>,
    /// Every configured and rewritten URL, for the scope test (L4).
    pub urls: Vec<String>,
}

/// Remote trust from the URLs git really uses. A remote whose configured
/// URL is trusted but whose fetch URL a rewrite sends elsewhere is an
/// error: its refs and `ls-remote` would answer from a repo the agent may
/// control, and treating it as untrusted would move the policy anchor to
/// local refs (L2).
pub fn remote_trust(git: &Git, scope: &CompiledScope) -> Result<RemoteTrust, PlanError> {
    let mut t = RemoteTrust::default();
    for r in remote_urls(git)? {
        if r.fetch.len() > 1 && r.all().any(|u| scope.remote_trusted(u)) {
            return Err(PlanError::Config(format!(
                "remote {}: it has more than one fetch URL ({}) and one matches scope.remotes; git fetches only the first, so keep one: git config --get-all remote.{}.url",
                r.name,
                r.fetch.join(", "),
                r.name
            )));
        }
        let configured = r.configured.iter().find(|u| scope.remote_trusted(u));
        let fetch = r.fetch.first().is_some_and(|u| scope.remote_trusted(u));
        if let (Some(c), false) = (configured, fetch) {
            return Err(PlanError::Config(format!(
                "remote {}: its URL {c} matches scope.remotes, but git fetches it from {} (a url.<base>.insteadOf rewrite); its refs cannot be trusted. Remove the rewrite (git config --get-regexp '^url\\.'), or add that URL to scope.remotes in the host config",
                r.name,
                r.fetch.first().map_or("nowhere", String::as_str)
            )));
        }
        if let (true, Some(url)) = (fetch, r.fetch.first()) {
            t.trusted.push(r.name.clone());
            t.trusted_urls.push(TrustedRemote {
                name: r.name.clone(),
                url: url.clone(),
            });
        }
        if fetch || configured.is_some() || r.push.iter().any(|u| scope.remote_trusted(u)) {
            t.push_trusted.push(r.name.clone());
        }
        t.urls.extend(r.configured);
        t.urls.extend(r.fetch);
        t.urls.extend(r.push);
    }
    t.urls.sort();
    t.urls.dedup();
    Ok(t)
}

/// Remote names whose fetch URL, as git uses it, matches `scope.remotes`
/// (R5, R14, L2); see [`remote_trust`].
pub fn trusted_remotes(git: &Git, scope: &CompiledScope) -> Result<Vec<String>, PlanError> {
    remote_trust(git, scope).map(|t| t.trusted)
}

/// The trusted remotes of `trust` with the record of what their server
/// reported (L2, R56). The server query finds git and ssh on the host's
/// `job.path_prepend` and then the system dirs (X1).
#[must_use]
pub fn remote_refs(
    dirs: &Dirs,
    env: &EnvSnapshot,
    job: &JobConfig,
    trust: &RemoteTrust,
) -> RemoteRefs {
    RemoteRefs::new(dirs, env, &job.path_prepend, trust.trusted_urls.clone())
}

/// R56: a base is trusted when its tree has a pass at `fast` or above, or
/// its commit is reachable from a trusted remote-tracking ref whose value
/// the trusted server reported (a forged tracking ref does not count).
fn base_trusted(
    git: &Git,
    store: &RecordStore,
    base: &Base,
    fp: &Fingerprint,
    remotes: &RemoteRefs,
) -> Result<bool, PlanError> {
    for tier in [Tier::Full, Tier::Fast] {
        let key = record_key(&base.tree, tier, fp);
        if store
            .read_usable(&key)
            .ok()
            .flatten()
            .is_some_and(|r| r.verdict == Verdict::Pass)
        {
            return Ok(true);
        }
    }
    if let Some(c) = &base.commit
        && !remotes.is_empty()
    {
        let mut args = vec![
            "for-each-ref".to_owned(),
            format!("--contains={c}"),
            "--format=%(objectname) %(refname)".to_owned(),
        ];
        args.extend(
            remotes
                .remotes()
                .iter()
                .map(|r| format!("refs/remotes/{}/", r.name)),
        );
        let out = git.run(&args)?;
        for line in String::from_utf8_lossy(&out).lines() {
            let Some((oid, refname)) = line.split_once(' ') else {
                continue;
            };
            let (Ok(oid), Some((remote, branch))) =
                (Oid::parse(oid), remotes.split_tracking(refname))
            else {
                continue;
            };
            if remotes.is_reported(remote, branch, &oid) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The exact fast selection when every Rust workspace map of the tree's
/// manifests is cached (the runner stores them); `None` otherwise. Runs
/// only `git diff-tree` (R51).
fn exact_selection(
    req: &PlanRequest<'_>,
    config: &crate::config::RepoConfig,
    entries: &[crate::gitx::TreeEntry],
    base: &Oid,
    fp: &Fingerprint,
) -> Option<Selection> {
    let changes = select::changed_paths(req.git, base, &req.tree).ok()?;
    if changes.is_empty() {
        return None;
    }
    let platform = Platform::current();
    let mut maps = BTreeMap::new();
    for root in steps::rust_roots(config, Tier::Fast, platform) {
        let key = select::rust::map_key(entries, &root, fp)?;
        maps.insert(root, Some(select::rust::load_cached(req.dirs, &key)?));
    }
    let other = select::detect::roots_from_tree(entries).other();
    steps::fast_plan(config, base, &changes, &maps, &other, platform)
        .ok()
        .map(|f| f.selection)
}

/// Plans a job for `req` (R74, L2, R56).
pub fn plan(req: &PlanRequest<'_>) -> Result<Plan, PlanError> {
    let host = &req.host.config;
    let scope = CompiledScope::new(&host.scope, req.dirs).map_err(PlanError::Config)?;
    let remotes = remote_refs(
        req.dirs,
        req.env,
        &host.job,
        &remote_trust(req.git, &scope)?,
    );
    let entries = req.git.ls_tree(&req.tree)?;
    let policy = policy::resolve(
        req.git,
        &entries,
        req.tip.as_ref(),
        &remotes,
        Some(&req.refname),
    )?;
    let config = &policy.config;
    let rules = config.ref_rules().map_err(PlanError::Config)?;
    // L16: no reuse for full jobs of full refs, or on --rerun; their
    // lookups accept only a full pass that ran every step fresh.
    let full_ref = rules.tier_for_ref(&req.refname) == Tier::Full;
    let allow_reuse = req.allow_reuse && !req.rerun && (req.tier == Tier::Fast || !full_ref);
    let fresh_only = req.tier == Tier::Full && (full_ref || !req.allow_reuse);
    let budgets = host.budget.with_overrides(&config.budget);
    let now = jiff::Timestamp::now();
    let id = JobId::generate(now);
    let job_env = JobEnv::base(&BaseInputs {
        env: req.env,
        dirs: req.dirs,
        job: &host.job,
        tmpdir: &req.dirs.job_dir(&id).join("tmp"),
    })
    .map_err(|e| PlanError::Config(e.to_string()))?;
    let mut env_files = Vec::new();
    let mut images: BTreeMap<ResourceName, String> = BTreeMap::new();
    for s in config.steps.iter().filter(|s| s.runs_in(req.tier)) {
        if let Some(p) = &s.env_file {
            env_files.push(
                EnvFile::read(&req.dirs.expand_tilde(p))
                    .map_err(|e| PlanError::Config(e.to_string()))?,
            );
        }
        for r in &s.resources {
            if let Some(i) = host.resource_image(r) {
                images.insert(r.clone(), i.to_owned());
            }
        }
    }
    let origin_dir: PathBuf = req
        .layout
        .worktree
        .clone()
        .unwrap_or_else(|| req.layout.common_dir.clone());
    let detected = select::detect::roots_from_tree(&entries);
    let mut rust_roots = steps::rust_roots(config, req.tier, Platform::current());
    rust_roots.extend(detected.rust.iter().cloned());
    let neutral = probe_dir(req.dirs, req.git, &[], &[])?;
    let rust_dirs = rust_probe_dirs(req.dirs, req.git, &entries, &rust_roots)?;
    let mut tools = ToolCache::load(&req.dirs.toolcache_file());
    let mut fp = fingerprint::compute(
        &FingerprintInputs {
            roots: kinds_roots(config, req.tier, &detected),
            job_env: &job_env,
            cwd: &neutral,
            rust_dirs: &rust_dirs,
            verify_root: Some(&host.verify.root(req.dirs)),
            host_config_hash: &req.host.hash,
            effective_config_hash: &config.effective_hash(),
            env_files: &env_files,
            images: &images,
        },
        &mut tools,
    )?;
    let _ = tools.save();
    fp.insert("policy-files", policy.files_hash());
    let key = record_key(&req.tree, req.tier, &fp);
    let store = RecordStore::new(req.dirs);

    let (select, note, needed) = match (&req.base, req.tier) {
        (_, Tier::Full) => (false, None, Needed::Exact(Selection::All)),
        (None, Tier::Fast) => (
            false,
            Some("no base".to_owned()),
            Needed::Exact(Selection::All),
        ),
        (Some(b), Tier::Fast) if b.tree == req.tree => {
            (false, Some("empty diff (R56)".to_owned()), Needed::Any)
        }
        (Some(b), Tier::Fast) => {
            let empty = req.git.object_format()?.empty_tree();
            if b.tree == empty {
                (
                    false,
                    Some("the base is the empty tree (R56)".to_owned()),
                    Needed::Exact(Selection::All),
                )
            } else if base_trusted(req.git, &store, b, &fp, &remotes)? {
                let needed = exact_selection(req, config, &entries, &b.tree, &fp)
                    .map_or_else(|| Needed::SameBase(b.tree.clone()), Needed::Exact);
                (true, None, needed)
            } else {
                (
                    false,
                    Some("the base has no record and no trusted remote has it (R56)".to_owned()),
                    Needed::Exact(Selection::All),
                )
            }
        }
    };
    let origin = Origin {
        worktree: origin_dir,
        refname: req.refname.clone(),
    };
    let mut env_pairs = Vec::new();
    for (k, v) in job_env.iter() {
        match (k.to_str(), v.to_str()) {
            (Some(k), Some(v)) => env_pairs.push((k.to_owned(), v.to_owned())),
            _ => {
                return Err(PlanError::Config(format!(
                    "job environment {}: not UTF-8",
                    k.to_string_lossy()
                )));
            }
        }
    }
    let spec = JobSpec {
        schema: SPEC_SCHEMA,
        id,
        key,
        tree: req.tree.clone(),
        tier: req.tier,
        fingerprint: fp,
        common_dir: req.layout.common_dir.clone(),
        repo_key: req.layout.repo_key(),
        origin,
        base_tree: req.base.as_ref().map(|b| b.tree.clone()),
        select,
        select_note: note,
        policy: PolicySpec::from_policy(&policy),
        host: host.clone(),
        budgets,
        job_env: env_pairs,
        allow_reuse,
        rerun: req.rerun,
        priority: req.priority,
        created: now,
    };
    Ok(Plan {
        spec,
        needed,
        fresh_only,
    })
}

/// The record lookup of R15 for a plan.
pub fn lookup(dirs: &Dirs, plan: &Plan) -> Result<Lookup, StoreError> {
    RecordStore::new(dirs).lookup(&LookupRequest {
        tree: &plan.spec.tree,
        tier: plan.spec.tier,
        fingerprint: &plan.spec.fingerprint,
        needed: &plan.needed,
        now: jiff::Timestamp::now(),
        fresh_only: plan.fresh_only,
    })
}

/// What [`start`] did.
#[derive(Debug)]
pub enum Started {
    /// A record answers the request (the race re-check after the claim).
    Hit(Box<Lookup>),
    /// This call created the job and started its runner.
    Created(JobId),
    /// Another job for the key runs; attach to it (R88).
    Attached(JobId),
}

/// Creates the job and starts its runner, or names the job that already
/// owns the key (R88). `exe` is the tollgate binary.
pub fn start(
    dirs: &Dirs,
    plan: &Plan,
    exe: &Path,
    env: &EnvSnapshot,
) -> Result<Started, PlanError> {
    let spec = &plan.spec;
    let io = |e: &dyn std::fmt::Display| PlanError::Io(e.to_string());
    for _ in 0..50 {
        match sched::claim_job(dirs, &spec.key, &spec.id).map_err(|e| io(&e))? {
            Claim::Owner(claim) => {
                // Re-check after the claim: the previous owner may have
                // written the record just before releasing the key.
                if !spec.rerun {
                    let found = lookup(dirs, plan)?;
                    if !matches!(found, Lookup::Miss) {
                        return Ok(Started::Hit(Box::new(found)));
                    }
                }
                let spec_json = spec.to_json().map_err(|e| io(&e))?;
                let meta = JobMeta {
                    id: spec.id.clone(),
                    key: spec.key.clone(),
                    tree: spec.tree.clone(),
                    tier: spec.tier,
                    origin: spec.origin.clone(),
                    priority: spec.priority,
                    created: spec.created,
                    state: JobState::Queued,
                };
                let store = JobStore::new(dirs);
                store
                    .create_with(&meta, &[("spec.json", &spec_json)])
                    .map_err(|e| io(&e))?;
                if let Err(e) = spawn::spawn(exe, dirs, &spec.id, claim.into_file(), env) {
                    let _ = store.transition(
                        &spec.id,
                        &[sched::StateKind::Queued],
                        JobState::Deferred {
                            reason: format!("runner did not start: {e}"),
                        },
                    );
                    return Err(io(&format!("cannot start the runner: {e}")));
                }
                return Ok(Started::Created(spec.id.clone()));
            }
            Claim::Running(Some(id)) => return Ok(Started::Attached(id)),
            Claim::Running(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    Err(PlanError::Io(
        "another job holds the key but its id cannot be read".into(),
    ))
}

/// How a check ended ([`settle`]).
#[derive(Debug)]
pub enum Settled {
    /// A record answers this plan's own lookup (R15, R79).
    Record(Box<Lookup>),
    /// This plan's job ended, or an attached job that checked exactly what
    /// this plan needs: its report.
    Report(Box<JobReport>),
    /// Still queued or running at the deadline.
    Running(JobId),
    /// The job is gone without a report (its runner died).
    Lost(String),
}

/// True when job `id` checks exactly what `plan` needs: same key (tree,
/// tier, fingerprint), same selection base and selection switch, and no
/// step reuse when `plan` needs every step fresh (L16).
fn same_check(dirs: &Dirs, id: &JobId, plan: &Plan) -> bool {
    let Ok(other) = JobSpec::read(dirs, id) else {
        return false;
    };
    let mine = &plan.spec;
    other.key == mine.key
        && other.tree == mine.tree
        && other.tier == mine.tier
        && other.base_tree == mine.base_tree
        && other.select == mine.select
        && (!plan.fresh_only || !other.allow_reuse)
}

/// Follows `started` to an answer for `plan` (R15, R32, R79, R88).
///
/// A job this plan created answers with its report. A job it attached to
/// (another check of the same key) may have checked another selection or
/// reused steps, so its report answers only when [`same_check`] holds;
/// otherwise, once it ends, this plan's own lookup decides, and on a miss
/// this plan starts its own job. `on_start` sees every job started or
/// attached on the way (for messages). The hooks use this, never the
/// attached job's verdict alone.
pub fn settle(
    dirs: &Dirs,
    plan: &Plan,
    exe: &Path,
    env: &EnvSnapshot,
    started: Started,
    deadline: Option<Instant>,
    on_start: &mut dyn FnMut(&Started),
) -> Result<Settled, PlanError> {
    let mut current = started;
    for _ in 0..8 {
        match current {
            Started::Hit(found) => return Ok(Settled::Record(found)),
            Started::Created(id) => {
                return Ok(match wait(dirs, &id, deadline) {
                    WaitEnd::Done(r) => Settled::Report(r),
                    WaitEnd::Running => Settled::Running(id),
                    WaitEnd::Lost(m) => Settled::Lost(m),
                });
            }
            Started::Attached(id) => {
                let same = same_check(dirs, &id, plan);
                match wait(dirs, &id, deadline) {
                    WaitEnd::Running => return Ok(Settled::Running(id)),
                    WaitEnd::Lost(m) => return Ok(Settled::Lost(m)),
                    WaitEnd::Done(r) if same => return Ok(Settled::Report(r)),
                    WaitEnd::Done(_) => {}
                }
                match lookup(dirs, plan)? {
                    Lookup::Miss => {}
                    found => return Ok(Settled::Record(Box::new(found))),
                }
                // The queue budget (R33) counts from now, not from when
                // this plan attached.
                let mut own = plan.clone();
                own.spec.created = jiff::Timestamp::now();
                current = start(dirs, &own, exe, env)?;
                on_start(&current);
            }
        }
    }
    Err(PlanError::Io(format!(
        "key {}: other jobs kept taking it; run the check again",
        plan.spec.key
    )))
}

/// How waiting for a job ended.
#[derive(Debug)]
pub enum WaitEnd {
    /// The job ended; its report.
    Done(Box<JobReport>),
    /// Still queued or running at the deadline.
    Running,
    /// The job is gone without a report (its runner died).
    Lost(String),
}

/// Waits for job `id` until it ends or `deadline` passes, holding a waiter
/// lock (R89) meanwhile.
pub fn wait(dirs: &Dirs, id: &JobId, deadline: Option<Instant>) -> WaitEnd {
    let store = JobStore::new(dirs);
    // An attached job's dir may not exist yet: register once it does.
    let mut waiter = None;
    let mut dead_once = false;
    loop {
        if waiter.is_none() {
            waiter = sched::register_waiter(&dirs.job_dir(id)).ok();
        }
        let meta = match store.read(id) {
            Ok(m) => m,
            Err(e) => {
                // An attached job may not have written job.json yet.
                if dead_once {
                    return WaitEnd::Lost(e.to_string());
                }
                dead_once = true;
                std::thread::sleep(Duration::from_millis(200));
                continue;
            }
        };
        let owner = sched::running_job(dirs, &meta.key).ok().flatten();
        if let JobState::Lost { reason } = &meta.state {
            return WaitEnd::Lost(format!("job {id} is lost: {reason}"));
        }
        if meta.state.is_terminal() {
            match JobReport::read(dirs, id) {
                Ok(Some(r)) => return WaitEnd::Done(Box::new(r)),
                // A queued job cancelled or superseded by another process:
                // its runner writes the report on its way out.
                Ok(None) if owner.as_ref() == Some(id) => {}
                Ok(None) if !dead_once => dead_once = true,
                Ok(None) => return WaitEnd::Lost(format!("job {id} ended without a report")),
                Err(e) => return WaitEnd::Lost(e.to_string()),
            }
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        if owner.as_ref() != Some(id) {
            // Seen twice in a row: the runner died without a final state.
            // Its leftover step processes still hold slots and the checkout
            // (R35, R85): stop them and mark the job lost.
            if dead_once {
                let reaped = match sched::reap_if_lost(dirs, id) {
                    Ok(true) => store
                        .read(id)
                        .ok()
                        .and_then(|m| match m.state {
                            JobState::Lost { reason } => Some(format!("; {reason}")),
                            _ => None,
                        })
                        .unwrap_or_default(),
                    _ => String::new(),
                };
                return WaitEnd::Lost(format!(
                    "job {id}: its runner is gone (see {}){reaped}",
                    dirs.job_dir(id).join("runner.log").display()
                ));
            }
            dead_once = true;
        } else {
            dead_once = false;
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return WaitEnd::Running;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toolchain_files_that_name_a_dir_are_found_r51() {
        let path = |t: &str| toolchain_path(t.as_bytes());
        assert_eq!(
            path("[toolchain]\npath = \"/opt/tc\"\n").as_deref(),
            Some("/opt/tc")
        );
        assert_eq!(path("[toolchain]\nchannel = \"1.89\"\n"), None);
        assert_eq!(path("nightly-2026-01-01\n"), None);
        assert_eq!(path("../tc\n").as_deref(), Some("../tc"));
        assert_eq!(path("[toolchain]\npath = 3\n").as_deref(), Some("?"));
    }
}
