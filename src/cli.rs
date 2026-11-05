//! CLI commands of the runner phase (R47, R48, R83, R89, R92, R93, R99,
//! L1, L14, L17): `check`, `wait`, `cancel`, `status`, `report`, `log`,
//! `run --here`, `config --effective|init`, `gc`, `audit`, `flaky` and the
//! hidden runner entry. `src/main.rs` parses arguments and calls these.
//!
//! Exit codes: 0 pass/ok, 1 fail (or a job ended without a pass), 2 usage
//! or internal error, 3 still running (`wait`, R99).

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::cache::record::{Record, Verdict};
use crate::cache::store::{Lookup, RecordStore};
use crate::cache::{Fingerprint, record_key};
use crate::config::check::REPO_CONFIG_FILE;
use crate::config::units::DurationSpec;
use crate::config::{HostConfig, LoadedHost, RepoConfig, Tier};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::gitx::{Git, Oid, RepoLayout};
use crate::ids::JobId;
use crate::locks::Priority;
use crate::plan::{self, Base, PlanRequest, Settled, Started, WaitEnd};
use crate::policy::{self, ConfigSource};
use crate::report::{self, JobReport};
use crate::runner::env::{BaseInputs, JobEnv};
use crate::runner::job::{self, JobSpec, PolicySpec, SPEC_SCHEMA};
use crate::sched::{CancelOutcome, JobState, JobStore, Origin};
use crate::select::detect;

/// What every command needs.
#[derive(Debug, Clone)]
pub struct Ctx {
    /// tollgate's environment.
    pub env: EnvSnapshot,
    /// Current dir.
    pub cwd: PathBuf,
    /// This binary (to start runners).
    pub exe: PathBuf,
}

fn fail(msg: impl std::fmt::Display) -> u8 {
    eprintln!("tollgate: {msg}");
    exit::BLOCK
}

struct Repo {
    dirs: Dirs,
    host: LoadedHost,
    layout: RepoLayout,
    git: Git,
}

impl Ctx {
    fn dirs(&self) -> Result<Dirs, String> {
        Dirs::from_env(&self.env).map_err(|e| e.to_string())
    }

    fn host(&self, dirs: &Dirs) -> Result<LoadedHost, String> {
        let host = HostConfig::load(dirs).map_err(|e| e.to_string())?;
        let v = host.config.validate();
        if !v.is_ok() {
            let errs: Vec<String> = v.errors.iter().map(ToString::to_string).collect();
            return Err(format!(
                "host config {}: {}",
                host.path.display(),
                errs.join("; ")
            ));
        }
        Ok(host)
    }

    fn repo(&self) -> Result<Repo, String> {
        let dirs = self.dirs()?;
        let host = self.host(&dirs)?;
        let layout = RepoLayout::discover(&Git::scrubbed(&self.env, &self.cwd))
            .map_err(|e| format!("not in a git repository: {e}"))?;
        let git = Git::scrubbed(&self.env, layout.hooks_cwd());
        Ok(Repo {
            dirs,
            host,
            layout,
            git,
        })
    }
}

/// `tollgate check` arguments (R99).
#[derive(Debug, Clone)]
pub struct CheckArgs {
    /// Tier (default `fast`).
    pub tier: Tier,
    /// `--tree T`.
    pub tree: Option<String>,
    /// `--rev R`.
    pub rev: Option<String>,
    /// `--wait`: until the job ends (bounded by `TOLLGATE_INLINE_CAP`).
    pub wait: bool,
    /// `--detach`: start and return.
    pub detach: bool,
    /// `--rerun`: drop the record and run again (R34).
    pub rerun: bool,
}

/// The tree, policy tip, base and ref of a check.
struct Target {
    tree: Oid,
    tip: Option<Oid>,
    base: Option<Base>,
    refname: String,
}

fn head_ref(git: &Git) -> String {
    git.run_line(["symbolic-ref", "-q", "HEAD"])
        .unwrap_or_else(|_| "HEAD".to_owned())
}

fn head_base(git: &Git) -> Result<(Option<Oid>, Option<Base>), String> {
    let head = git
        .rev_parse_verify("HEAD^{commit}")
        .map_err(|e| e.to_string())?;
    let base = match &head {
        Some(c) => Base {
            tree: git
                .tree_of(c.as_str())
                .map_err(|e| e.to_string())?
                .ok_or("HEAD has no tree")?,
            commit: Some(c.clone()),
        },
        None => Base {
            tree: git.object_format().map_err(|e| e.to_string())?.empty_tree(),
            commit: None,
        },
    };
    Ok((head, Some(base)))
}

fn target(git: &Git, tree: Option<&str>, rev: Option<&str>) -> Result<Target, String> {
    let refname = head_ref(git);
    if let Some(r) = rev {
        let commit = git
            .rev_parse_verify(&format!("{r}^{{commit}}"))
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{r} is not a commit"))?;
        let t = git
            .tree_of(commit.as_str())
            .map_err(|e| e.to_string())?
            .ok_or("no tree")?;
        let parent = git
            .rev_parse_verify(&format!("{commit}^1"))
            .map_err(|e| e.to_string())?;
        let base = match parent {
            Some(p) => Base {
                tree: git
                    .tree_of(p.as_str())
                    .map_err(|e| e.to_string())?
                    .ok_or("no tree")?,
                commit: Some(p),
            },
            None => Base {
                tree: git.object_format().map_err(|e| e.to_string())?.empty_tree(),
                commit: None,
            },
        };
        let named = git
            .run_line(["rev-parse", "--symbolic-full-name", r])
            .ok()
            .filter(|n| n.starts_with("refs/heads/"));
        return Ok(Target {
            tree: t,
            tip: Some(commit),
            base: Some(base),
            refname: named.unwrap_or(refname),
        });
    }
    let (tip, base) = head_base(git)?;
    let t = match tree {
        Some(x) => git
            .tree_of(x)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("{x} is not a tree"))?,
        None => git.write_tree().map_err(|e| e.to_string())?,
    };
    Ok(Target {
        tree: t,
        tip,
        base,
        refname,
    })
}

fn header(r: &JobReport) -> String {
    format!(
        "tollgate: {} tree {} tier {} job {}",
        r.verdict_text().to_uppercase(),
        r.tree.short(12),
        r.tier,
        r.job_id
    )
}

fn print_report(r: &JobReport) {
    let mut out = std::io::stdout().lock();
    for l in report::render(r, &header(r)) {
        let _ = writeln!(out, "{l}");
    }
}

fn report_exit(r: &JobReport) -> u8 {
    if r.passed() { exit::OK } else { exit::FAIL }
}

fn print_record(dirs: &Dirs, rec: &Record, what: &str) -> u8 {
    match JobReport::read(dirs, &rec.job_id) {
        Ok(Some(r)) => print_report(&r),
        _ => println!(
            "tollgate: {} tree {} tier {} job {}",
            what,
            rec.tree.short(12),
            rec.tier,
            rec.job_id
        ),
    }
    if rec.verdict == Verdict::Pass {
        exit::OK
    } else {
        exit::FAIL
    }
}

fn inline_cap(env: &EnvSnapshot) -> Option<Duration> {
    env.get_str("TOLLGATE_INLINE_CAP")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn wait_and_print(dirs: &Dirs, id: &JobId, deadline: Option<Instant>) -> u8 {
    match plan::wait(dirs, id, deadline) {
        WaitEnd::Done(r) => {
            print_report(&r);
            report_exit(&r)
        }
        WaitEnd::Running => {
            println!("tollgate: job {id} is still running; wait with: tollgate wait {id}");
            exit::RUNNING
        }
        WaitEnd::Lost(m) => {
            eprintln!("tollgate: {m}");
            exit::FAIL
        }
    }
}

/// `tollgate check` (R99).
pub fn check(ctx: &Ctx, a: &CheckArgs) -> u8 {
    let repo = match ctx.repo() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let t = match target(&repo.git, a.tree.as_deref(), a.rev.as_deref()) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let plan = match plan::plan(&PlanRequest {
        env: &ctx.env,
        dirs: &repo.dirs,
        host: &repo.host,
        layout: &repo.layout,
        git: &repo.git,
        tree: t.tree,
        tier: a.tier,
        tip: t.tip,
        base: t.base,
        refname: t.refname,
        allow_reuse: true,
        priority: if a.detach {
            Priority::Prewarm
        } else {
            Priority::Hook
        },
        rerun: a.rerun,
    }) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    if a.rerun {
        let _ = RecordStore::new(&repo.dirs).remove(&plan.spec.key);
    } else {
        match plan::lookup(&repo.dirs, &plan) {
            Ok(Lookup::Miss) => {}
            Ok(found) => return print_lookup(&repo.dirs, &found),
            Err(e) => return fail(e),
        }
    }
    let started = match plan::start(&repo.dirs, &plan, &ctx.exe, &ctx.env) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let mut say = |s: &Started| match s {
        Started::Hit(_) => {}
        Started::Created(id) => println!(
            "tollgate: job {id} started: tier {} tree {}",
            plan.spec.tier,
            plan.spec.tree.short(12)
        ),
        Started::Attached(id) => println!("tollgate: attached to running job {id}"),
    };
    say(&started);
    if a.detach {
        return match &started {
            Started::Hit(found) => print_lookup(&repo.dirs, found),
            Started::Created(id) | Started::Attached(id) => {
                println!("tollgate: wait with: tollgate wait {id}");
                exit::OK
            }
        };
    }
    let deadline = if a.wait {
        inline_cap(&ctx.env).map(|d| Instant::now() + d)
    } else {
        Some(
            Instant::now()
                + plan
                    .spec
                    .budgets
                    .inline_for_hook(ctx.env.get_str("TOLLGATE_INLINE_CAP"), a.tier),
        )
    };
    match plan::settle(
        &repo.dirs, &plan, &ctx.exe, &ctx.env, started, deadline, &mut say,
    ) {
        Ok(Settled::Record(found)) => print_lookup(&repo.dirs, &found),
        Ok(Settled::Report(r)) => {
            print_report(&r);
            report_exit(&r)
        }
        Ok(Settled::Running(id)) => {
            println!("tollgate: job {id} is still running; wait with: tollgate wait {id}");
            exit::RUNNING
        }
        Ok(Settled::Lost(m)) => {
            eprintln!("tollgate: {m}");
            exit::FAIL
        }
        Err(e) => fail(e),
    }
}

fn print_lookup(dirs: &Dirs, found: &Lookup) -> u8 {
    match found {
        Lookup::Pass(r) => print_record(dirs, r, "PASS"),
        Lookup::Fail(r) => {
            let code = print_record(dirs, r, "FAIL");
            println!("tollgate: stored fail; run again with: tollgate check --rerun");
            code
        }
        Lookup::Environmental(r) => {
            let code = print_record(dirs, r, "ERROR");
            println!(
                "tollgate: stored {:?} for {} min (R34); run again with: tollgate check --rerun",
                r.verdict,
                r.ttl_secs.unwrap_or(900) / 60
            );
            code
        }
        Lookup::Miss => exit::FAIL,
    }
}

/// `tollgate wait <job> [--timeout D]` (R99, L17): 0 pass, 1 fail, 3
/// still running. The default timeout is `TOLLGATE_INLINE_CAP` when set,
/// else 100 s (under the Bash default timeout).
pub fn wait(ctx: &Ctx, job: &str, timeout: Option<&str>) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let id = match JobId::parse(job) {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    let limit = match timeout {
        Some(t) => match DurationSpec::parse(t) {
            Ok(d) => d.get(),
            Err(e) => return fail(e),
        },
        None => inline_cap(&ctx.env).unwrap_or(crate::config::host::DEFAULT_INLINE_CAP),
    };
    wait_and_print(&dirs, &id, Some(Instant::now() + limit))
}

/// `tollgate cancel <job>` (R89).
pub fn cancel(ctx: &Ctx, job: &str) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let id = match JobId::parse(job) {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    match JobStore::new(&dirs).request_cancel(&id) {
        Ok(CancelOutcome::Cancelled) => {
            println!("tollgate: job {id} cancelled (it was queued)");
            exit::OK
        }
        Ok(CancelOutcome::Requested) => {
            // A runner that died cannot act on the request (R35).
            if matches!(crate::sched::reap_if_lost(&dirs, &id), Ok(true)) {
                println!(
                    "tollgate: job {id}: its runner was gone; its processes are stopped and the job is lost"
                );
            } else {
                println!("tollgate: job {id}: cancel requested; its runner stops the steps");
            }
            exit::OK
        }
        Ok(CancelOutcome::AlreadyEnded(s)) => {
            println!("tollgate: job {id} already ended: {}", state_text(&s));
            exit::OK
        }
        Err(e) => {
            eprintln!("tollgate: job {id}: {e}");
            exit::FAIL
        }
    }
}

fn state_text(s: &JobState) -> String {
    match s {
        JobState::Queued => "queued".into(),
        JobState::Running { started, pid } => format!("running since {started} (pid {pid})"),
        JobState::Finished { verdict } => format!("finished: {verdict:?}").to_lowercase(),
        JobState::Superseded => "superseded".into(),
        JobState::Cancelled => "cancelled".into(),
        JobState::Deferred { reason } => format!("deferred: {reason}"),
        JobState::Lost { reason } => format!("lost: {reason}"),
    }
}

#[derive(Debug, Serialize)]
struct TierStatus {
    verdict: String,
    job: Option<JobId>,
}

#[derive(Debug, Serialize)]
struct TreeStatus {
    label: String,
    tree: Oid,
    fast: Option<TierStatus>,
    full: Option<TierStatus>,
}

#[derive(Debug, Serialize)]
struct JobLine {
    id: JobId,
    tier: Tier,
    tree: Oid,
    refname: String,
    state: String,
}

#[derive(Debug, Serialize)]
struct Unchecked {
    /// Newest commit (first-parent walk) whose tree has a pass.
    newest_checked: Option<Oid>,
    /// Commits above it without one.
    above: usize,
    /// Commits looked at.
    scanned: usize,
}

#[derive(Debug, Serialize)]
struct StatusJson {
    repo: PathBuf,
    refname: String,
    trees: Vec<TreeStatus>,
    jobs: Vec<JobLine>,
    unchecked: Unchecked,
    policy_line: Option<String>,
    /// Item 17: commits on the branch made without the gate.
    unverified: Vec<crate::hook::unverified::UnverifiedCommit>,
}

const UNCHECKED_SCAN: usize = 200;

fn tier_status(found: Lookup) -> Option<TierStatus> {
    match found {
        Lookup::Pass(r) | Lookup::Fail(r) | Lookup::Environmental(r) => Some(TierStatus {
            verdict: format!("{:?}", r.verdict).to_lowercase(),
            job: Some(r.job_id),
        }),
        Lookup::Miss => None,
    }
}

fn pass_of(store: &RecordStore, tree: &Oid, fps: &[(Tier, Fingerprint)]) -> bool {
    fps.iter().any(|(tier, fp)| {
        store
            .read_usable(&record_key(tree, *tier, fp))
            .ok()
            .flatten()
            .is_some_and(|r| r.verdict == Verdict::Pass)
    })
}

/// `tollgate status [--rev R] [--json]` (R92, L1).
pub fn status(ctx: &Ctx, rev: Option<&str>, json: bool) -> u8 {
    let repo = match ctx.repo() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let git = &repo.git;
    let refname = head_ref(git);
    let mut targets: Vec<(String, Target)> = Vec::new();
    let rev_label = rev.unwrap_or("HEAD");
    if git
        .rev_parse_verify(&format!("{rev_label}^{{commit}}"))
        .ok()
        .flatten()
        .is_some()
    {
        match target(git, None, Some(rev_label)) {
            Ok(t) => targets.push((rev_label.to_owned(), t)),
            Err(e) => return fail(e),
        }
    }
    if rev.is_none()
        && let Ok(t) = target(git, None, None)
        && targets.first().is_none_or(|(_, h)| h.tree != t.tree)
    {
        targets.push(("index".to_owned(), t));
    }
    let store = RecordStore::new(&repo.dirs);
    let mut trees = Vec::new();
    let mut fps: Vec<(Tier, Fingerprint)> = Vec::new();
    let mut policy_line = None;
    for (label, t) in &targets {
        let mut st = TreeStatus {
            label: label.clone(),
            tree: t.tree.clone(),
            fast: None,
            full: None,
        };
        for tier in [Tier::Fast, Tier::Full] {
            let p = match plan::plan(&PlanRequest {
                env: &ctx.env,
                dirs: &repo.dirs,
                host: &repo.host,
                layout: &repo.layout,
                git,
                tree: t.tree.clone(),
                tier,
                tip: t.tip.clone(),
                base: t.base.clone(),
                refname: t.refname.clone(),
                allow_reuse: true,
                priority: Priority::Hook,
                rerun: false,
            }) {
                Ok(p) => p,
                Err(e) => return fail(e),
            };
            if fps.len() < 2 {
                fps.push((tier, p.spec.fingerprint.clone()));
                policy_line = policy_line.or(p.spec.policy.line.clone());
            }
            let found = plan::lookup(&repo.dirs, &p).unwrap_or(Lookup::Miss);
            let s = tier_status(found);
            match tier {
                Tier::Fast => st.fast = s,
                Tier::Full => st.full = s,
            }
        }
        trees.push(st);
    }
    // L1: the newest commit with a record, and how many above it have none.
    let mut unchecked = Unchecked {
        newest_checked: None,
        above: 0,
        scanned: 0,
    };
    if let Ok(out) = git.run([
        "log",
        "--first-parent",
        "--format=%H %T",
        "-n",
        &UNCHECKED_SCAN.to_string(),
        rev_label,
    ]) {
        for line in String::from_utf8_lossy(&out).lines() {
            let Some((c, t)) = line.split_once(' ') else {
                continue;
            };
            let (Ok(c), Ok(t)) = (Oid::parse(c), Oid::parse(t)) else {
                continue;
            };
            unchecked.scanned += 1;
            if pass_of(&store, &t, &fps) {
                unchecked.newest_checked = Some(c);
                break;
            }
            unchecked.above += 1;
        }
    }
    // Item 17: commits made without the gate that are on this branch and
    // whose tree has not passed since.
    let unverified: Vec<_> =
        crate::hook::unverified::pending(&repo.dirs, &repo.layout, |t| pass_of(&store, t, &fps))
            .into_iter()
            .filter(|u| {
                git.output(["merge-base", "--is-ancestor", u.commit.as_str(), rev_label])
                    .is_ok_and(|o| o.status.success())
            })
            .collect();
    let jobs = active_jobs(&repo.dirs, &repo.layout.common_dir);
    if json {
        let s = StatusJson {
            repo: repo.layout.repo_dir(),
            refname,
            trees,
            jobs,
            unchecked,
            policy_line,
            unverified,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&s).unwrap_or_else(|_| "{}".into())
        );
        return exit::OK;
    }
    println!("repo {} on {refname}", repo.layout.repo_dir().display());
    if let Some(l) = &policy_line {
        println!("{l}");
    }
    for t in &trees {
        let show = |s: &Option<TierStatus>| {
            s.as_ref().map_or_else(
                || "none".to_owned(),
                |s| {
                    format!(
                        "{} (job {})",
                        s.verdict,
                        s.job.as_ref().map_or("?", JobId::as_str)
                    )
                },
            )
        };
        println!(
            "{} tree {}: fast {}, full {}",
            t.label,
            t.tree.short(12),
            show(&t.fast),
            show(&t.full)
        );
    }
    match &unchecked.newest_checked {
        Some(c) if unchecked.above == 0 => {
            println!("unchecked: none ({} has a pass record)", c.short(12));
        }
        Some(c) => println!(
            "unchecked: {} commit(s) above {} (the newest commit with a pass record)",
            unchecked.above,
            c.short(12)
        ),
        None => println!(
            "unchecked: no pass record in the last {} commit(s)",
            unchecked.scanned
        ),
    }
    if unverified.is_empty() {
        println!("unverified: none (no commit here was made without the gate)");
    } else {
        println!(
            "unverified: {} commit(s) made without the gate (--no-verify?); check each with tollgate check --rev <commit>:",
            unverified.len()
        );
        for u in &unverified {
            println!(
                "  {} {} ({}, {}){}",
                u.commit.short(12),
                u.refname,
                u.hook,
                u.at.strftime("%Y-%m-%d %H:%M"),
                u.command
                    .as_deref()
                    .map(|c| format!(": {c}"))
                    .unwrap_or_default()
            );
        }
    }
    for j in &jobs {
        println!(
            "job {} {} tree {} {}: {}",
            j.id,
            j.tier,
            j.tree.short(12),
            j.refname,
            j.state
        );
    }
    exit::OK
}

fn active_jobs(dirs: &Dirs, common_dir: &Path) -> Vec<JobLine> {
    let store = JobStore::new(dirs);
    store
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|m| !m.state.is_terminal())
        .filter(|m| JobSpec::read(dirs, &m.id).is_ok_and(|s| s.common_dir == common_dir))
        .map(|m| JobLine {
            state: state_text(&m.state),
            id: m.id,
            tier: m.tier,
            tree: m.tree,
            refname: m.origin.refname,
        })
        .collect()
}

/// `tollgate report <job|tree> [--json]` (R92).
pub fn report_cmd(ctx: &Ctx, target_arg: &str, json: bool) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let report = if let Ok(id) = JobId::parse(target_arg) {
        match JobReport::read(&dirs, &id) {
            Ok(Some(r)) => r,
            Ok(None) => return fail(format!("job {id} has no report (yet)")),
            Err(e) => return fail(e),
        }
    } else {
        let git = Git::scrubbed(&ctx.env, &ctx.cwd);
        let tree = match git.tree_of(target_arg) {
            Ok(Some(t)) => t,
            _ => return fail(format!("{target_arg} is neither a job id nor a tree")),
        };
        let mut records: Vec<Record> = RecordStore::new(&dirs)
            .list()
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.tree == tree)
            .collect();
        records.sort_by_key(|r| std::cmp::Reverse(r.finished));
        match records
            .iter()
            .find_map(|r| JobReport::read(&dirs, &r.job_id).ok().flatten())
        {
            Some(r) => r,
            None => return fail(format!("no record for tree {}", tree.short(12))),
        }
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        print_report(&report);
    }
    report_exit(&report)
}

/// `tollgate log <job> <step> [--tail N]` (R92).
pub fn log(ctx: &Ctx, job: &str, step: &str, tail: Option<usize>) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let id = match JobId::parse(job) {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    let file = JobReport::read(&dirs, &id)
        .ok()
        .flatten()
        .and_then(|r| r.steps.into_iter().find(|s| s.name == step))
        .and_then(|s| s.log)
        .unwrap_or_else(|| format!("{}.log", report::slug(step)));
    let path = dirs.job_dir(&id).join(&file);
    let Ok(bytes) = std::fs::read(&path) else {
        return fail(format!("no log {}", path.display()));
    };
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    let from = tail.map_or(0, |n| lines.len().saturating_sub(n));
    let mut out = std::io::stdout().lock();
    for l in &lines[from..] {
        let _ = writeln!(out, "{l}");
    }
    exit::OK
}

/// The effective config of the working tree for `run --here` and
/// `config`: its `tollgate.toml`, else detection (R65).
fn worktree_config(root: &Path) -> Result<(RepoConfig, ConfigSource, Vec<String>), String> {
    let path = root.join(REPO_CONFIG_FILE);
    match std::fs::read_to_string(&path) {
        Ok(text) => {
            let c = RepoConfig::from_toml(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            let blob = Oid::parse(&"0".repeat(40)).map_err(|e| e.clone())?;
            Ok((c, ConfigSource::File { blob }, Vec::new()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let (c, notes) = detect::detect_dir(root).map_err(|e| e.to_string())?;
            Ok((c, ConfigSource::Detected, notes))
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// `run --here` arguments (R47).
#[derive(Debug, Clone, Copy)]
pub struct HereArgs {
    /// Tier.
    pub tier: Tier,
    /// `--report junit`.
    pub junit: bool,
    /// `--no-host-locks`.
    pub no_host_locks: bool,
}

/// Where `run --here` writes `report.json`, `junit.xml` and logs.
pub const HERE_OUT: &str = "tollgate-report";

/// `tollgate run --tier T --here [--report junit] [--no-host-locks]` (R47).
pub fn run_here(ctx: &Ctx, a: HereArgs) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let host = match ctx.host(&dirs) {
        Ok(h) => h,
        Err(e) => return fail(e),
    };
    let git = Git::scrubbed(&ctx.env, &ctx.cwd);
    let layout = RepoLayout::discover(&git).ok();
    let workdir = layout
        .as_ref()
        .and_then(|l| l.worktree.clone())
        .unwrap_or_else(|| ctx.cwd.clone());
    let (config, source, notes) = match worktree_config(&workdir) {
        Ok(c) => c,
        Err(e) => return fail(e),
    };
    let v = config.validate();
    if !v.is_ok() {
        let errs: Vec<String> = v.errors.iter().map(ToString::to_string).collect();
        return fail(format!("{REPO_CONFIG_FILE}: {}", errs.join("; ")));
    }
    let out = workdir.join(HERE_OUT);
    let now = jiff::Timestamp::now();
    let id = JobId::generate(now);
    let job_env = match JobEnv::base(&BaseInputs {
        env: &ctx.env,
        dirs: &dirs,
        job: &host.config.job,
        tmpdir: &out.join("tmp"),
    }) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    let tree = git
        .tree_of("HEAD")
        .ok()
        .flatten()
        .unwrap_or_else(|| crate::gitx::ObjectFormat::Sha1.empty_tree());
    let spec = JobSpec {
        schema: SPEC_SCHEMA,
        id,
        key: crate::ids::RecordKey::from_hash(&blake3::hash(b"tollgate run --here")),
        tree,
        tier: a.tier,
        fingerprint: Fingerprint::new(),
        common_dir: layout
            .as_ref()
            .map_or_else(|| workdir.clone(), |l| l.common_dir.clone()),
        repo_key: crate::ids::RepoKey::of_realpath(&workdir),
        origin: Origin {
            worktree: workdir.clone(),
            refname: "HEAD".into(),
        },
        base_tree: None,
        select: false,
        select_note: Some("run --here checks everything".into()),
        policy: PolicySpec {
            commit: None,
            anchor: None,
            // R69 in CI: the cap counts from HEAD's committer date (never
            // after today, see the runner); an unborn HEAD counts from
            // today.
            committer_date: git
                .run_line(["log", "-1", "--format=%cs", "HEAD"])
                .ok()
                .and_then(|d| d.parse().ok()),
            nextest_configs: BTreeMap::new(),
            line: None,
            overlay: BTreeMap::new(),
            baselines: BTreeMap::new(),
            config: config.clone(),
            source,
            notes,
        },
        budgets: host.config.budget.with_overrides(&config.budget),
        host: host.config.clone(),
        job_env: job_env
            .iter()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect(),
        allow_reuse: false,
        rerun: true,
        priority: Priority::Hook,
        created: now,
    };
    // The repo's own nextest config applies in CI (no policy base).
    let mut spec = spec;
    for s in config
        .steps
        .iter()
        .filter(|s| s.kind == crate::config::repo::StepKind::Nextest)
    {
        let root = crate::steps::step_root(s);
        if let Ok(text) = std::fs::read_to_string(workdir.join(&root).join(".config/nextest.toml"))
        {
            spec.policy.nextest_configs.insert(root, text);
        }
    }
    // The baselines in the tree apply in CI (no policy base, R94).
    for s in &config.steps {
        let kind = match s.kind {
            crate::config::repo::StepKind::PyrightBaseline => crate::steps::baseline::Kind::Pyright,
            crate::config::repo::StepKind::PytestBaseline => crate::steps::baseline::Kind::Pytest,
            _ => continue,
        };
        let rel = crate::steps::step_root(s).join(kind.file());
        if let Ok(text) = std::fs::read_to_string(workdir.join(&rel)) {
            spec.policy.baselines.insert(rel, text);
        }
    }
    let use_locks = host.exists && !a.no_host_locks;
    let r = job::run_here(&dirs, spec, &workdir, &out, &ctx.env, use_locks);
    // R47, R73: a case per step plus the nextest suites.
    if a.junit
        && let Err(e) = std::fs::write(out.join("junit.xml"), crate::ci::junit(&r, &out))
    {
        eprintln!("tollgate: cannot write junit.xml: {e}");
    }
    print_report(&r);
    report_exit(&r)
}

/// `tollgate config --effective` (R65): the config jobs on `HEAD` use.
pub fn config_effective(ctx: &Ctx) -> u8 {
    let repo = match ctx.repo() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let scope = match crate::config::CompiledScope::new(&repo.host.config.scope, &repo.dirs) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let remotes = match plan::remote_trust(&repo.git, &scope) {
        Ok(t) => plan::remote_refs(&repo.dirs, &ctx.env, &t),
        Err(e) => return fail(e),
    };
    let (tip, tree) = match repo.git.rev_parse_verify("HEAD^{commit}") {
        Ok(Some(c)) => {
            let t = repo.git.tree_of(c.as_str()).ok().flatten();
            (Some(c), t)
        }
        _ => (None, repo.git.write_tree().ok()),
    };
    let Some(tree) = tree else {
        return fail("no tree to read the policy for");
    };
    let entries = match repo.git.ls_tree(&tree) {
        Ok(e) => e,
        Err(e) => return fail(e),
    };
    let own = head_ref(&repo.git);
    let p = match policy::resolve(&repo.git, &entries, tip.as_ref(), &remotes, Some(&own)) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let source = match &p.source {
        ConfigSource::File { blob } => format!("tollgate.toml (blob {})", blob.short(12)),
        ConfigSource::Detected => "detection (R65): the policy commit has no tollgate.toml".into(),
    };
    println!("# effective tollgate config for HEAD");
    println!("# source: {source}");
    match &p.base.commit {
        Some(c) => println!(
            "# policy commit: {}{} (L2)",
            c.short(12),
            p.base
                .anchor
                .as_deref()
                .map(|a| format!(", merge-base with {a}"))
                .unwrap_or_default()
        ),
        None => println!("# policy commit: none (unborn branch): the tree's own files"),
    }
    if let Some(l) = p.line() {
        println!("# {l}");
    }
    for n in &p.notes {
        println!("# note: {n}");
    }
    match p.config.to_toml() {
        Ok(t) => {
            print!("{t}");
            exit::OK
        }
        Err(e) => fail(e),
    }
}

const NEXTEST_TEMPLATE: &str = "# nextest config. tollgate adds its own profiles tollgate-fast and\n# tollgate-full with retries, timeouts, JUnit and the pg test group (R72);\n# settings here take priority. Changes apply after they merge to a full ref (L2).\n\n[profile.default]\n";

/// `tollgate config init [--nextest]` (R65): writes the detected config.
pub fn config_init(ctx: &Ctx, nextest: bool) -> u8 {
    let layout = match RepoLayout::discover(&Git::scrubbed(&ctx.env, &ctx.cwd)) {
        Ok(l) => l,
        Err(e) => return fail(format!("not in a git repository: {e}")),
    };
    let Some(root) = layout.worktree else {
        return fail("bare repository: no work tree to write tollgate.toml in");
    };
    let path = root.join(REPO_CONFIG_FILE);
    if path.exists() {
        return fail(format!("{} exists; not overwritten", path.display()));
    }
    let (config, notes) = match detect::detect_dir(&root) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let mut text = String::from(
        "# tollgate repo config (R63), written by `tollgate config init` from detection (R65).\n# Review it, then commit it; it applies after it merges to a full ref (L2).\n",
    );
    for n in &notes {
        text.push_str(&format!("# note: {n}\n"));
    }
    match config.to_toml() {
        Ok(t) => text.push_str(&t),
        Err(e) => return fail(e),
    }
    if let Err(e) = std::fs::write(&path, text) {
        return fail(format!("{}: {e}", path.display()));
    }
    println!("wrote {}", path.display());
    if nextest {
        let np = root.join(".config/nextest.toml");
        if np.exists() {
            println!("{} exists; not overwritten", np.display());
        } else if let Err(e) = std::fs::create_dir_all(root.join(".config"))
            .and_then(|()| std::fs::write(&np, NEXTEST_TEMPLATE))
        {
            return fail(format!("{}: {e}", np.display()));
        } else {
            println!("wrote {}", np.display());
        }
    }
    exit::OK
}

/// `tollgate gc [--all]` (R48).
pub fn gc(ctx: &Ctx, all: bool) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let host = match ctx.host(&dirs) {
        Ok(h) => h,
        Err(e) => return fail(e),
    };
    let r = crate::gc::gc(&dirs, &host.config, &ctx.env, all);
    println!(
        "gc: removed {} record(s), {} job dir(s), {} log file(s), {} step pass(es), {} verify checkout(s), {} ticket/lock file(s)",
        r.records, r.jobs, r.logs, r.steps, r.checkouts, r.tickets
    );
    exit::OK
}

/// Parses `--since`: a date `YYYY-MM-DD`, `<n>d` days, or a duration.
fn since(text: &str) -> Result<jiff::Timestamp, String> {
    let now = jiff::Timestamp::now();
    if let Ok(d) = text.parse::<jiff::civil::Date>() {
        return d
            .to_zoned(jiff::tz::TimeZone::system())
            .map(|z| z.timestamp())
            .map_err(|e| e.to_string());
    }
    let secs = if let Some(days) = text.strip_suffix('d') {
        days.trim()
            .parse::<i64>()
            .map_err(|e| format!("--since {text:?}: {e}"))?
            * 86_400
    } else {
        i64::try_from(DurationSpec::parse(text)?.get().as_secs()).unwrap_or(i64::MAX)
    };
    jiff::Timestamp::from_second(now.as_second().saturating_sub(secs)).map_err(|e| e.to_string())
}

fn dir_size(dir: &Path) -> u64 {
    crate::runner::checkout::dir_size(dir)
}

/// `tollgate audit [--since D]` (R83): records with duration, log size and
/// version, so a 0 s pass or an old-version record stands out.
pub fn audit(ctx: &Ctx, since_arg: Option<&str>) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let from = match since_arg.map(since).transpose() {
        Ok(f) => f,
        Err(e) => return fail(e),
    };
    let records = match RecordStore::new(&dirs).list() {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    println!(
        "finished              tree         tier verdict dur      logs     version job                      flags"
    );
    for r in records
        .iter()
        .filter(|r| from.is_none_or(|f| r.finished >= f))
    {
        let logs = dir_size(&dirs.job_dir(&r.job_id));
        let ran_steps = r
            .steps
            .iter()
            .any(|s| s.status != crate::cache::record::StepStatus::Skipped && s.duration_ms > 0);
        let mut flags = Vec::new();
        if r.verdict == Verdict::Pass && r.duration_ms < 1000 && ran_steps {
            flags.push("FAST-PASS");
        }
        if r.tollgate_version != crate::VERSION {
            flags.push("OLD-VERSION");
        }
        if !dirs.job_report(&r.job_id).is_file() {
            flags.push("NO-REPORT");
        }
        println!(
            "{} {} {:<4} {:<7} {:>7.1}s {:>7}K {:<7} {} {}",
            r.finished.strftime("%Y-%m-%dT%H:%M:%S"),
            r.tree.short(12),
            r.tier,
            format!("{:?}", r.verdict).to_lowercase(),
            r.duration_ms as f64 / 1000.0,
            logs / 1024,
            r.tollgate_version,
            r.job_id,
            flags.join(",")
        );
    }
    exit::OK
}

/// `tollgate flaky [--days N]` (R93).
pub fn flaky(ctx: &Ctx, days: u32) -> u8 {
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    match report::flaky_counts(&dirs, days, jiff::Timestamp::now()) {
        Ok(counts) if counts.is_empty() => {
            println!("no flaky tests in the last {days} day(s)");
            exit::OK
        }
        Ok(counts) => {
            for (test, n, last) in counts {
                println!("{n:>4}  {test}  (last {})", last.strftime("%Y-%m-%d %H:%M"));
            }
            exit::OK
        }
        Err(e) => fail(e),
    }
}

/// The hidden runner entry (`tollgate __run-job <id> --lock-fd 3`).
pub fn run_job(ctx: &Ctx, job: &str, lock_fd: Option<i32>) -> u8 {
    let _lock = match lock_fd.map(crate::runner::spawn::adopt_lock).transpose() {
        Ok(l) => l,
        Err(e) => return fail(format!("lock fd: {e}")),
    };
    let dirs = match ctx.dirs() {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let id = match JobId::parse(job) {
        Ok(i) => i,
        Err(e) => return fail(e),
    };
    job::run_job(&dirs, &id, &ctx.env)
}
