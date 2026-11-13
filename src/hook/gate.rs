//! The decision shared by the gate hooks (R14, R15, R31, R32, R34, R91,
//! L17).
//!
//! Each gate hook turns its input into one [`Check`] per tree (a commit
//! has one, a push one per branch). [`decide`] plans every check, looks up
//! its record, starts or attaches the missing jobs, waits for all of them
//! until one inline budget ends, and prints one result per check. Every
//! exit path is an explicit allow or deny (R31): an error denies with its
//! message. A deny at the inline budget names the job and prints one
//! command that waits for it and then repeats the git command (L17).

use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::cache::record::Verdict;
use crate::cache::store::Lookup;
use crate::config::{CompiledScope, HostConfig, LoadedHost, RefRules, Tier};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::gitx::{Git, Oid, RepoLayout};
use crate::ids::JobId;
use crate::locks::Priority;
use crate::metrics::{self, HookOutcome};
use crate::plan::{self, Base, Plan, PlanRequest, Settled, Started};
use crate::policy;
use crate::remote_refs::RemoteRefs;
use crate::report::{self, JobReport};

/// When a hook process started and how long the repo's own hook (R7)
/// took. The logged hook time (item 50) runs from `started`, so process
/// start, config, scope and remote loading and the staged-tree work are
/// in it; `stats` leaves out `repo_hook`, which is not tollgate's time.
#[derive(Debug, Clone, Copy)]
pub struct HookClock {
    /// Entry of `main` in the hook process.
    pub started: Instant,
    /// The repo hook's run time; `None` when the repo has none.
    pub repo_hook: Option<Duration>,
}

/// What a gate hook needs, loaded once.
#[derive(Debug)]
pub struct Gate<'a> {
    /// Hook name, for messages.
    pub hook: &'static str,
    /// The hook's environment.
    pub env: &'a EnvSnapshot,
    /// The running binary (starts job runners).
    pub exe: &'a Path,
    /// tollgate's dirs.
    pub dirs: Dirs,
    /// Host config.
    pub host: LoadedHost,
    /// The repo.
    pub layout: RepoLayout,
    /// Scrubbed git in the repo (R52).
    pub git: Git,
    /// Compiled `[scope]` (L4).
    pub scope: CompiledScope,
    /// Every remote URL, configured and as git uses it.
    pub remote_urls: Vec<String>,
    /// Remotes whose fetch URL, as git uses it, is trusted (R14(2), L2).
    pub trusted: Vec<String>,
    /// Remotes a push to which is a push to a trusted remote (R5, R20).
    pub push_trusted: Vec<String>,
    /// The trusted remotes' URLs and what their server reported (L2,
    /// R14(2)).
    pub remote_refs: RemoteRefs,
    /// The hook's start, for the logged hook time.
    pub clock: HookClock,
}

impl<'a> Gate<'a> {
    /// Loads host config, scope and remotes for `layout`. `dirs` come
    /// from [`super::hook_dirs`] (R8).
    pub fn open(
        hook: &'static str,
        env: &'a EnvSnapshot,
        exe: &'a Path,
        layout: RepoLayout,
        dirs: Dirs,
        clock: HookClock,
    ) -> Result<Self, String> {
        let host = HostConfig::load(&dirs).map_err(|e| e.to_string())?;
        let v = host.config.validate();
        if !v.is_ok() {
            let errs: Vec<String> = v.errors.iter().map(ToString::to_string).collect();
            return Err(format!(
                "host config {}: {}",
                host.path.display(),
                errs.join("; ")
            ));
        }
        let git = Git::scrubbed(env, layout.hooks_cwd());
        let scope = CompiledScope::new(&host.config.scope, &dirs)?;
        let trust = plan::remote_trust(&git, &scope).map_err(|e| e.to_string())?;
        let remote_refs = plan::remote_refs(&dirs, env, &host.config.job, &trust, &git, &layout);
        Ok(Self {
            hook,
            env,
            exe,
            dirs,
            host,
            layout,
            git,
            scope,
            remote_urls: trust.urls,
            trusted: trust.trusted,
            push_trusted: trust.push_trusted,
            remote_refs,
            clock,
        })
    }

    /// L4: the repo is in scope by its path or a trusted remote. Item 33:
    /// a repo whose recorded trusted remote is gone (or whose record is
    /// unusable) stays in scope, so its gate denies: removing the remote
    /// that put it in scope must not take it out of the gate.
    #[must_use]
    pub fn in_scope(&self) -> bool {
        self.scope
            .contains(&self.layout.repo_dir(), &self.remote_urls)
            || self.remote_refs.record_denial().is_some()
    }

    /// The ref rules of the policy that applies to new commit `tip` on
    /// `own_ref` (L2, R27, R20). `tree` is the tree under test.
    pub fn ref_rules(
        &self,
        tree: &Oid,
        tip: Option<&Oid>,
        own_ref: &str,
    ) -> Result<RefRules, String> {
        self.policy(tree, tip, own_ref)?.config.ref_rules()
    }

    /// The policy that applies to new commit `tip` on `own_ref` (L2), with
    /// its policy commit. `tree` is the tree under test.
    pub fn policy(
        &self,
        tree: &Oid,
        tip: Option<&Oid>,
        own_ref: &str,
    ) -> Result<policy::Policy, String> {
        let entries = self.git.ls_tree(tree).map_err(|e| e.to_string())?;
        policy::resolve(&self.git, &entries, tip, &self.remote_refs, Some(own_ref))
            .map_err(|e| e.to_string())
    }

    /// The current branch (`refs/heads/x`), or `HEAD` when detached.
    #[must_use]
    pub fn head_ref(&self) -> String {
        self.git
            .run_line(["symbolic-ref", "-q", "HEAD"])
            .ok()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "HEAD".to_owned())
    }

    /// `HEAD` as a selection base (R17): its commit and tree, or the empty
    /// tree on an unborn branch.
    pub fn head_base(&self) -> Result<(Option<Oid>, Base), String> {
        let head = self
            .git
            .rev_parse_verify("HEAD^{commit}")
            .map_err(|e| e.to_string())?;
        let base = match &head {
            Some(c) => Base {
                tree: self
                    .git
                    .tree_of(c.as_str())
                    .map_err(|e| e.to_string())?
                    .ok_or("HEAD has no tree")?,
                commit: Some(c.clone()),
            },
            None => Base {
                tree: self
                    .git
                    .object_format()
                    .map_err(|e| e.to_string())?
                    .empty_tree(),
                commit: None,
            },
        };
        Ok((head, base))
    }
}

/// R14 outcome 2: what may stand in for a missing `full` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteVerify {
    /// `pre-push`: the pushed commit equals a trusted remote's current
    /// `refs/heads/<branch>` (`git ls-remote`).
    Commit {
        /// The pushed commit.
        oid: Oid,
        /// Branch name.
        branch: String,
    },
    /// Merge commit: the merged tree equals the tree of a trusted remote's
    /// current `refs/heads/<branch>` (the target branch).
    Tree {
        /// Branch name.
        branch: String,
    },
}

/// One tree a hook gates.
#[derive(Debug, Clone)]
pub struct Check {
    /// The tree (R40).
    pub tree: Oid,
    /// Required tier.
    pub tier: Tier,
    /// The new commit whose policy applies (L2).
    pub tip: Option<Oid>,
    /// Selection base (R55).
    pub base: Option<Base>,
    /// The job's ref: origin (R89), policy and reuse rules (L16).
    pub refname: String,
    /// R14 outcome 2, for `full` checks of `pre-merge-commit`/`pre-push`.
    pub remote_verify: Option<RemoteVerify>,
    /// The command that runs this check again after a stored fail.
    pub rerun_hint: String,
}

/// R14 outcome 2: the current `refs/heads/<branch>` of each of `remotes`
/// (trusted remotes), from `git ls-remote` against its trusted URL at
/// hook time, run outside the repo so the repo's own config (an
/// `uploadpack` or `sshCommand`) cannot change who answers
/// ([`RemoteRefs::server_heads`]). The remote-tracking ref is only a hint:
/// a remote whose fetched tip does not match is not asked (no network wait
/// for a merge or push that cannot match).
fn remote_verified(gate: &Gate<'_>, check: &Check, remotes: &[String]) -> Option<String> {
    let rv = check.remote_verify.as_ref()?;
    let branch = match rv {
        RemoteVerify::Commit { branch, .. } | RemoteVerify::Tree { branch } => branch,
    };
    let refname = format!("refs/heads/{branch}");
    let matches = |oid: &Oid| match rv {
        RemoteVerify::Commit { oid: mine, .. } => mine == oid,
        RemoteVerify::Tree { .. } => gate
            .git
            .tree_of(oid.as_str())
            .ok()
            .flatten()
            .is_some_and(|t| t == check.tree),
    };
    for remote in remotes {
        let Some(trusted) = gate.remote_refs.get(remote) else {
            continue;
        };
        let tracking = format!("refs/remotes/{remote}/{branch}");
        if !gate
            .git
            .rev_parse_verify(&tracking)
            .ok()
            .flatten()
            .is_some_and(|o| matches(&o))
        {
            continue;
        }
        let Ok(heads) = gate.remote_refs.server_heads(trusted) else {
            continue;
        };
        if let Some(oid) = heads.get(&refname).filter(|o| matches(o)) {
            return Some(format!("{remote} {refname} at {}", oid.short(12)));
        }
    }
    None
}

/// R39: a deny names `tollgate doctor --repo .` (never `rm`) when a git
/// lock file older than 2 minutes exists that the parent git does not
/// hold open.
fn stale_lock_hint(gate: &Gate<'_>) {
    let parent = std::os::unix::process::parent_id();
    let old = crate::gitx::lockfiles::old_locks(&gate.layout.common_dir, Duration::from_secs(120));
    if let Some(l) = old
        .iter()
        .find(|l| !crate::gitx::lockfiles::holds_open(parent, &l.path))
    {
        eprintln!(
            "tollgate: a git lock file is older than 2 minutes ({}); check it with: tollgate doctor --repo .",
            l.path.display()
        );
    }
}

fn header(gate: &Gate<'_>, check: &Check, verdict: &str, job: Option<&JobId>) -> String {
    format!(
        "tollgate: DENIED {} {} tree {} tier {} verdict {verdict}{}",
        gate.hook,
        check.refname,
        check.tree.short(12),
        check.tier,
        job.map(|j| format!(" job {j}")).unwrap_or_default()
    )
}

fn allow_line(gate: &Gate<'_>, check: &Check, how: &str) {
    eprintln!(
        "tollgate: pass {} {} tree {} tier {} ({how})",
        gate.hook,
        check.refname,
        check.tree.short(12),
        check.tier
    );
}

fn print_report(r: &JobReport, head: &str) {
    for l in report::render(r, head) {
        eprintln!("{l}");
    }
}

/// Prints a stored non-pass record; always a deny.
fn deny_record(gate: &Gate<'_>, check: &Check, found: &Lookup) {
    let (Lookup::Fail(rec) | Lookup::Environmental(rec) | Lookup::Pass(rec)) = found else {
        return;
    };
    let verdict = format!("{:?}", rec.verdict).to_lowercase();
    let head = header(gate, check, &verdict, Some(&rec.job_id));
    match JobReport::read(&gate.dirs, &rec.job_id) {
        Ok(Some(r)) => print_report(&r, &head),
        _ => eprintln!("{head}"),
    }
    match found {
        Lookup::Environmental(r) => eprintln!(
            "tollgate: stored {verdict} (R34): no new job for {} min after it; to run it now: {}",
            r.ttl_secs.unwrap_or(900) / 60,
            check.rerun_hint
        ),
        _ => eprintln!(
            "tollgate: stored fail (R34); after a fix, commit again; to run the same tree again: {}",
            check.rerun_hint
        ),
    }
}

/// How one check ended, before printing; with what the metrics log
/// keeps of it (item 50).
enum Outcome {
    Allowed(HookOutcome, Option<JobId>),
    Denied(HookOutcome, Option<JobId>),
    Running(JobId),
}

impl Outcome {
    fn allowed(&self) -> bool {
        matches!(self, Self::Allowed(..))
    }

    fn metric(&self) -> (HookOutcome, Option<&JobId>) {
        match self {
            Self::Allowed(k, j) | Self::Denied(k, j) => (*k, j.as_ref()),
            Self::Running(id) => (HookOutcome::RefusedCap, Some(id)),
        }
    }
}

/// `inline`: the record came from a job this hook waited for.
fn lookup_outcome(gate: &Gate<'_>, check: &Check, found: &Lookup, inline: bool) -> Outcome {
    match found {
        Lookup::Pass(rec) => {
            allow_line(gate, check, &format!("record of job {}", rec.job_id));
            let kind = if inline {
                HookOutcome::Passed
            } else {
                HookOutcome::CacheHit
            };
            Outcome::Allowed(kind, Some(rec.job_id.clone()))
        }
        Lookup::Miss => {
            eprintln!("{}", header(gate, check, "none", None));
            eprintln!("tollgate: no record and no job");
            Outcome::Denied(HookOutcome::Error, None)
        }
        Lookup::Fail(rec) | Lookup::Environmental(rec) => {
            deny_record(gate, check, found);
            Outcome::Denied(HookOutcome::Failed, Some(rec.job_id.clone()))
        }
    }
}

fn settled_outcome(gate: &Gate<'_>, check: &Check, settled: Settled) -> Outcome {
    match settled {
        Settled::Record(found) => lookup_outcome(gate, check, &found, true),
        Settled::Report(r) if r.passed() => {
            allow_line(gate, check, &format!("job {}", r.job_id));
            Outcome::Allowed(HookOutcome::Passed, Some(r.job_id))
        }
        Settled::Report(r) => {
            let head = header(gate, check, &r.verdict_text(), Some(&r.job_id));
            print_report(&r, &head);
            if r.verdict.is_some_and(|v| v != Verdict::Pass) {
                eprintln!("tollgate: to run the same tree again: {}", check.rerun_hint);
            }
            Outcome::Denied(HookOutcome::Failed, Some(r.job_id))
        }
        Settled::Running(id) => {
            eprintln!("{}", header(gate, check, "running", Some(&id)));
            Outcome::Running(id)
        }
        Settled::Lost(m) => {
            eprintln!("{}", header(gate, check, "lost", None));
            eprintln!("tollgate: {m}");
            Outcome::Denied(HookOutcome::Error, None)
        }
    }
}

/// An id for one hook run (8 hex digits) from this process and `t`.
fn run_id(t: jiff::Timestamp) -> String {
    let mut h = blake3::Hasher::new();
    h.update(&std::process::id().to_le_bytes());
    h.update(&t.as_nanosecond().to_le_bytes());
    h.finalize().to_hex()[..8].to_owned()
}

/// One metrics line per check (item 50); never fails the hook. The lines
/// share `t`, `ms` and a run id, so `stats` takes one hook time per run.
/// `ms` runs from the hook process's start ([`HookClock`]).
fn record_metrics(gate: &Gate<'_>, checks: &[Check], outcomes: &[Outcome]) {
    let lines: Vec<(Option<Tier>, HookOutcome, Option<&JobId>)> = outcomes
        .iter()
        .zip(checks)
        .map(|(o, c)| {
            let (outcome, job) = o.metric();
            (Some(c.tier), outcome, job)
        })
        .collect();
    record_hook_lines(gate, &lines);
}

/// Metrics lines of one hook run: (tier, outcome, job) per check or
/// refused ref (item 50, R102); never fails the hook.
pub fn record_hook_lines(gate: &Gate<'_>, lines: &[(Option<Tier>, HookOutcome, Option<&JobId>)]) {
    let ms_of = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
    let ms = ms_of(gate.clock.started.elapsed());
    let repo_hook_ms = gate.clock.repo_hook.map(ms_of);
    let t = jiff::Timestamp::now();
    let repo = metrics::repo_name(&gate.layout.common_dir);
    let run = run_id(t);
    let events: Vec<metrics::Event> = lines
        .iter()
        .map(|(tier, outcome, job)| {
            metrics::Event::Hook(metrics::HookEvent {
                t,
                hook: gate.hook.to_owned(),
                repo: repo.clone(),
                tier: *tier,
                outcome: *outcome,
                job: job.cloned(),
                ms,
                repo_hook_ms,
                run: Some(run.clone()),
            })
        })
        .collect();
    metrics::record(&gate.dirs, &events);
}

/// Gates `checks`; returns the hook's exit code (0 allow, 1 deny).
/// `retry` is the git command to repeat after `tollgate wait` (L17);
/// `ask_remotes` are the trusted remotes R14(2) asks.
pub fn decide(gate: &Gate<'_>, checks: &[Check], retry: &str, ask_remotes: &[String]) -> u8 {
    let mut outcomes: Vec<Outcome> = Vec::new();
    let mut pending: Vec<(usize, Plan, Started)> = Vec::new();
    for (i, check) in checks.iter().enumerate() {
        let planned = plan::plan(&PlanRequest {
            env: gate.env,
            dirs: &gate.dirs,
            host: &gate.host,
            layout: &gate.layout,
            git: &gate.git,
            tree: check.tree.clone(),
            tier: check.tier,
            tip: check.tip.clone(),
            base: check.base.clone(),
            refname: check.refname.clone(),
            allow_reuse: true,
            priority: Priority::Hook,
            rerun: false,
        });
        let p = match planned {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{}", header(gate, check, "error", None));
                eprintln!("tollgate: {e}");
                outcomes.push(Outcome::Denied(HookOutcome::Error, None));
                continue;
            }
        };
        match plan::lookup(&gate.dirs, &p) {
            Ok(Lookup::Miss) => {}
            Ok(found) => {
                outcomes.push(lookup_outcome(gate, check, &found, false));
                continue;
            }
            Err(e) => {
                eprintln!("{}", header(gate, check, "error", None));
                eprintln!("tollgate: record store: {e}");
                outcomes.push(Outcome::Denied(HookOutcome::Error, None));
                continue;
            }
        }
        if check.tier == Tier::Full
            && let Some(how) = remote_verified(gate, check, ask_remotes)
        {
            allow_line(gate, check, &format!("remote-verified (R14): {how}"));
            outcomes.push(Outcome::Allowed(HookOutcome::RemoteVerified, None));
            continue;
        }
        match plan::start(&gate.dirs, &p, gate.exe, gate.env) {
            Ok(Started::Hit(found)) => outcomes.push(lookup_outcome(gate, check, &found, false)),
            Ok(s) => {
                announce(gate, check, &s);
                // Replaced after settle.
                outcomes.push(Outcome::Denied(HookOutcome::Error, None));
                pending.push((i, p, s));
            }
            Err(e) => {
                eprintln!("{}", header(gate, check, "error", None));
                eprintln!("tollgate: {e}");
                outcomes.push(Outcome::Denied(HookOutcome::Error, None));
            }
        }
    }
    let budget = pending
        .iter()
        .map(|(_, p, _)| {
            p.spec
                .budgets
                .inline_for_hook(gate.env.get_str("TOLLGATE_INLINE_CAP"), p.spec.tier)
        })
        .max()
        .unwrap_or(Duration::ZERO);
    let deadline = Instant::now() + budget;
    for (i, p, s) in pending {
        let check = &checks[i];
        let mut say = |s: &Started| announce(gate, check, s);
        outcomes[i] = match plan::settle(
            &gate.dirs,
            &p,
            gate.exe,
            gate.env,
            s,
            Some(deadline),
            &mut say,
        ) {
            Ok(settled) => settled_outcome(gate, check, settled),
            Err(e) => {
                eprintln!("{}", header(gate, check, "error", None));
                eprintln!("tollgate: {e}");
                Outcome::Denied(HookOutcome::Error, None)
            }
        };
    }
    let running: Vec<&JobId> = outcomes
        .iter()
        .filter_map(|o| match o {
            Outcome::Running(id) => Some(id),
            _ => None,
        })
        .collect();
    if !running.is_empty() {
        let waits: Vec<String> = running
            .iter()
            .map(|id| format!("tollgate wait {id}"))
            .collect();
        eprintln!(
            "tollgate: no result inside the inline budget of {}s (R32); the job continues detached.",
            budget.as_secs()
        );
        eprintln!(
            "tollgate: when it passes, this command allows: {} && {retry}",
            waits.join(" && ")
        );
    }
    // Item 17: trees a gate allowed count as checked, for the post hooks.
    let store = crate::cache::store::RecordStore::new(&gate.dirs);
    for (o, c) in outcomes.iter().zip(checks) {
        if o.allowed() {
            store.mark_passed_tree(&c.tree);
        }
    }
    record_metrics(gate, checks, &outcomes);
    if outcomes.iter().all(Outcome::allowed) {
        crate::exit::OK
    } else {
        stale_lock_hint(gate);
        for l in super::unverified::deny_note(&gate.dirs, &gate.layout) {
            eprintln!("{l}");
        }
        crate::exit::FAIL
    }
}

fn announce(gate: &Gate<'_>, check: &Check, s: &Started) {
    match s {
        Started::Hit(_) => {}
        Started::Created(id) => eprintln!(
            "tollgate: {} {}: job {id} started: tier {} tree {}",
            gate.hook,
            check.refname,
            check.tier,
            check.tree.short(12)
        ),
        Started::Attached(id) => eprintln!(
            "tollgate: {} {}: attached to running job {id}",
            gate.hook, check.refname
        ),
    }
}

/// The git command a deny tells the agent to repeat (L17): the parent
/// git's own arguments when readable, else `fallback`.
#[must_use]
pub fn retry_command(fallback: &str) -> String {
    match super::argv::parent_git_args() {
        Some(args) => super::argv::git_command_text(&args),
        None => fallback.to_owned(),
    }
}

/// Resolves the hook's `GIT_INDEX_FILE` (relative in the main worktree)
/// against its cwd; `<git dir>/index` when unset.
#[must_use]
pub fn hook_index_file(env: &EnvSnapshot, cwd: &Path, layout: &RepoLayout) -> std::path::PathBuf {
    match env.get_nonempty("GIT_INDEX_FILE") {
        Some(p) => {
            let p = Path::new(p);
            if p.is_absolute() {
                p.to_owned()
            } else {
                cwd.join(p)
            }
        }
        None => layout.git_dir.join("index"),
    }
}

/// `git write-tree` of the hook's index (R17), run on a private copy so
/// tollgate never locks or rewrites the agent's index files (R52, T14).
pub fn write_tree(gate: &Gate<'_>, index: &Path) -> Result<Oid, String> {
    let tmp = gate.dirs.state_dir().join("tmp");
    crate::fsx::ensure_dir(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    let copy = tmp.join(format!("index-{}", crate::fsx::unique_suffix()));
    match std::fs::copy(index, &copy) {
        Ok(_) => {}
        // No index file: git reads an empty index.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot copy the index {}: {e}", index.display())),
    }
    let tree = gate.git.clone().with_index_file(&copy).write_tree();
    let _ = std::fs::remove_file(&copy);
    let mut lock: OsString = copy.into_os_string();
    lock.push(".lock");
    let _ = std::fs::remove_file(lock);
    tree.map_err(|e| e.to_string())
}
