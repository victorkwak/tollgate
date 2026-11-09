//! `tollgate bench` (L20): replays commits concurrently from N worktrees
//! of one repo through the real hooks and reports what the gate cost.
//!
//! The source repo is never written. The bench makes a scratch dir
//! (`<parent>/tollgate-bench-<unique>`) that holds everything:
//!
//! - `bin/tollgate` and `hooks/<name>`: hard links (or copies) of this
//!   binary, so the hooks find no `install.json` beside them and use the
//!   bench's dirs, never an install's (R8);
//! - `config/`, `state/`, `data/`: the `XDG_*` dirs of every git and
//!   tollgate process the bench starts, with a host config written from
//!   the flags (resource slots, `pg_max_threads`, `verify.min_free`) and
//!   the scratch dir as the only scope root (L4);
//! - `repo/`: `git clone --shared --no-checkout` of the source plus its
//!   local branches (the L2 policy anchors), and `wt/<i>`: one worktree
//!   per scenario slot, on its own branch, at the source's `HEAD` commit;
//! - `verify/`: the verify checkouts (L15).
//!
//! Before the commits, a warm-up `tollgate check` of the start commit
//! gives every worktree a checked base (R56) and stored step passes to
//! reuse (L16), as in daily work where the base was checked. Then each
//! round, every worktree applies its scenario's edits, all start
//! `git commit` together, and retries commit the same tree again. git's
//! trace2 events give each hook's start-to-exit time. Job reports give
//! queue waits (R85, R87), overhead and reuse; samplers give CPU load
//! and, with `--pg-url`, Postgres connections (`psql`).
//!
//! At the end the bench cancels the jobs that still run, waits for every
//! runner to exit, kills what is left (Linux, by its environment), and
//! removes the scratch dir (`--keep` keeps it).

pub mod report;
pub mod sample;
pub mod scenario;
pub mod trace;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::cli::Ctx;
use crate::config::HostConfig;
use crate::config::host::{ResourceSpec, ScopeConfig};
use crate::config::units::SizeSpec;
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::ids::{JobId, ResourceName};
use crate::report::JobReport;
use crate::sched::JobStore;

use report::{
    Attempt, AttemptKind, BenchReport, Cleanup, Collected, HookOutcome, JobRow, Warm, classify,
    round_ms,
};
use sample::{PgTarget, Samplers};
use scenario::{Place, Scenario, ScenarioFile};

/// `tollgate bench` arguments.
#[derive(Debug, Clone)]
pub struct BenchArgs {
    /// The source repo (any dir in it).
    pub repo: PathBuf,
    /// The scenario file.
    pub scenarios: PathBuf,
    /// N: must equal the sum of the scenarios' worktree counts.
    pub worktrees: Option<u32>,
    /// Commits per worktree.
    pub rounds: u32,
    /// Parent of the scratch dir (default `$TMPDIR`, else `/tmp`).
    pub scratch: Option<PathBuf>,
    /// Keep the scratch dir.
    pub keep: bool,
    /// `cpu` slots.
    pub cpu: Option<u32>,
    /// `pg` slots.
    pub pg: Option<u32>,
    /// `nextest.pg_max_threads`.
    pub pg_max_threads: Option<u32>,
    /// A host config to start from (job env, nextest, budgets).
    pub base_config: Option<PathBuf>,
    /// `verify.min_free`.
    pub min_free: Option<String>,
    /// `TOLLGATE_INLINE_CAP` for the commits, in seconds.
    pub inline_cap: Option<u64>,
    /// Postgres URL to sample.
    pub pg_url: Option<String>,
    /// The `psql` program.
    pub psql: PathBuf,
    /// Sample interval in milliseconds.
    pub sample_ms: u64,
    /// Run the warm-up check.
    pub warm: bool,
    /// JSON on stdout instead of text.
    pub json: bool,
    /// Also write the JSON report here.
    pub out: Option<PathBuf>,
    /// Exit 1 when a measured L19 budget is over. The L19 tests assert CPU
    /// time, which load does not move; this asserts the wall-clock p95
    /// under the bench's concurrent commits.
    pub enforce_budgets: bool,
}

/// How long cleanup waits for cancelled jobs and exiting runners.
const CANCEL_WAIT: Duration = Duration::from_secs(30);

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// SIGINT and SIGTERM stop the run; cleanup still runs.
fn trap_signals() {
    let handler = on_signal as extern "C" fn(libc::c_int);
    // SAFETY: the handler only stores to an atomic, which is
    // async-signal-safe.
    unsafe {
        libc::signal(libc::SIGINT, handler as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handler as libc::sighandler_t);
    }
}

fn stopped() -> bool {
    STOP.load(Ordering::SeqCst)
}

fn ms(d: Duration) -> f64 {
    round_ms(d.as_secs_f64() * 1000.0)
}

/// The scratch dir's parts.
#[derive(Debug, Clone)]
struct Layout {
    root: PathBuf,
}

impl Layout {
    fn bin(&self) -> PathBuf {
        self.root.join("bin/tollgate")
    }
    fn hooks(&self) -> PathBuf {
        self.root.join("hooks")
    }
    fn no_hooks(&self) -> PathBuf {
        self.root.join("no-hooks")
    }
    fn clone_dir(&self) -> PathBuf {
        self.root.join("repo")
    }
    fn worktree(&self, i: u32) -> PathBuf {
        self.root.join("wt").join(i.to_string())
    }
    fn trace(&self, name: &str) -> PathBuf {
        self.root.join("trace").join(format!("{name}.json"))
    }
    fn state_home(&self) -> PathBuf {
        self.root.join("state")
    }
}

/// Variables passed from the caller to every process the bench starts.
/// Everything else (a session's hook injection, `XDG_*`, `TOLLGATE_*`) is
/// cleared.
const PASS_THROUGH: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "TZ",
    "TMPDIR",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "DOCKER_HOST",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
];

/// The environment of the bench's git and tollgate processes.
#[derive(Debug, Clone)]
struct BenchEnv {
    base: BTreeMap<OsString, OsString>,
    inline_cap: Option<u64>,
}

impl BenchEnv {
    fn new(caller: &EnvSnapshot, layout: Option<&Layout>, inline_cap: Option<u64>) -> Self {
        let mut base: BTreeMap<OsString, OsString> = PASS_THROUGH
            .iter()
            .filter_map(|k| caller.get(k).map(|v| (OsString::from(k), v.to_owned())))
            .collect();
        let mut set = |k: &str, v: &std::ffi::OsStr| {
            base.insert(k.into(), v.to_owned());
        };
        set("LANG", "C".as_ref());
        set("LC_ALL", "C".as_ref());
        for k in ["GIT_AUTHOR", "GIT_COMMITTER"] {
            set(&format!("{k}_NAME"), "tollgate bench".as_ref());
            set(&format!("{k}_EMAIL"), "bench@tollgate.invalid".as_ref());
        }
        if let Some(l) = layout {
            set("XDG_CONFIG_HOME", l.root.join("config").as_os_str());
            set("XDG_STATE_HOME", l.state_home().as_os_str());
            set("XDG_DATA_HOME", l.root.join("data").as_os_str());
        }
        Self { base, inline_cap }
    }

    fn snapshot(&self) -> EnvSnapshot {
        EnvSnapshot::from_pairs(self.base.clone())
    }

    fn command(&self, program: &Path, dir: &Path) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear()
            .envs(&self.base)
            .current_dir(dir)
            .stdin(Stdio::null());
        cmd
    }

    /// git with `core.hooksPath` = `hooks` and the user config's
    /// background work and signing turned off.
    fn git(&self, hooks: &Path, dir: &Path) -> Command {
        let mut cmd = self.command(crate::gitx::program(), dir);
        let config: [(&str, &std::ffi::OsStr); 5] = [
            ("core.hooksPath", hooks.as_os_str()),
            ("commit.gpgSign", "false".as_ref()),
            ("maintenance.auto", "false".as_ref()),
            ("gc.auto", "0".as_ref()),
            ("core.fsmonitor", "false".as_ref()),
        ];
        cmd.env("GIT_CONFIG_COUNT", config.len().to_string());
        for (i, (k, v)) in config.iter().enumerate() {
            cmd.env(format!("GIT_CONFIG_KEY_{i}"), k)
                .env(format!("GIT_CONFIG_VALUE_{i}"), v);
        }
        cmd
    }

    /// A `git commit` through the bench's hooks, traced to `trace`.
    fn commit(&self, layout: &Layout, dir: &Path, trace: &Path) -> Command {
        let mut cmd = self.git(&layout.hooks(), dir);
        cmd.env("GIT_TRACE2_EVENT", trace);
        if let Some(cap) = self.inline_cap {
            cmd.env("TOLLGATE_INLINE_CAP", cap.to_string());
        }
        cmd
    }

    /// The `psql` environment: the base plus the caller's `PG*` variables.
    fn psql(&self, caller: &EnvSnapshot) -> Vec<(OsString, OsString)> {
        self.base
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .chain(
                caller
                    .iter()
                    .filter(|(k, _)| k.to_str().is_some_and(|k| k.starts_with("PG")))
                    .map(|(k, v)| (k.to_owned(), v.to_owned())),
            )
            .collect()
    }
}

/// Runs `cmd`; its trimmed stdout, or an error with its stderr.
fn run_cmd(cmd: &mut Command, what: &str) -> Result<String, String> {
    let out = cmd.output().map_err(|e| format!("{what}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{what}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// What a [`run_stoppable`] child printed and how it ended.
struct Ran {
    status: std::process::ExitStatus,
    stdout: String,
    stderr: String,
}

/// Runs `cmd` with stdout and stderr in `<base>.out` and `<base>.err`
/// (no pipe can fill and block it), polling every `poll`. The child leads
/// its own process group, which the hooks git starts join. A signal to the
/// bench (SIGINT, SIGTERM) kills that whole group, so cleanup starts at
/// once with no hook left waiting; the jobs the hooks started run detached
/// and are cancelled by cleanup.
fn run_stoppable(cmd: &mut Command, base: &Path, poll: Duration) -> std::io::Result<Ran> {
    let out_path = base.with_extension("out");
    let err_path = base.with_extension("err");
    let mut child = cmd
        .stdout(std::fs::File::create(&out_path)?)
        .stderr(std::fs::File::create(&err_path)?)
        .process_group(0)
        .spawn()?;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if stopped() {
            // The child is not reaped yet, so its pid (the group id)
            // cannot be reused.
            let _ = crate::procs::signal_group(child.id().cast_signed(), libc::SIGKILL);
            break child.wait()?;
        }
        std::thread::sleep(poll);
    };
    let read = |p: &Path| {
        let text = String::from_utf8_lossy(&std::fs::read(p).unwrap_or_default()).into_owned();
        let _ = std::fs::remove_file(p);
        text
    };
    Ok(Ran {
        status,
        stdout: read(&out_path),
        stderr: read(&err_path),
    })
}

/// Poll interval of a timed `git commit`: its wall time is exact to
/// about this.
const COMMIT_POLL: Duration = Duration::from_millis(1);

/// Poll interval of untimed waits.
const SLOW_POLL: Duration = Duration::from_millis(20);

/// The scratch dir; removed on drop unless [`Scratch::finish`] ran.
#[derive(Debug)]
struct Scratch {
    path: PathBuf,
    done: bool,
}

impl Scratch {
    fn create(parent: &Path) -> Result<Self, String> {
        loop {
            let path = parent.join(format!("tollgate-bench-{}", crate::fsx::unique_suffix()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path, done: false }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(format!("{}: {e}", path.display())),
            }
        }
    }

    /// Removes the dir unless `keep`; returns whether it is gone.
    fn finish(mut self, keep: bool) -> Result<bool, String> {
        self.done = true;
        if keep {
            return Ok(false);
        }
        std::fs::remove_dir_all(&self.path)
            .map(|()| true)
            .map_err(|e| format!("{}: {e}", self.path.display()))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if !self.done {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

/// What the bench checked before it made anything.
#[derive(Debug)]
struct Prepared {
    scenarios: ScenarioFile,
    worktrees: u32,
    parent: PathBuf,
    common_dir: PathBuf,
    head: String,
    host: HostConfig,
}

fn prepare(ctx: &Ctx, a: &BenchArgs) -> Result<Prepared, String> {
    if a.rounds == 0 {
        return Err("--rounds must be at least 1".into());
    }
    if a.sample_ms < 10 {
        return Err("--sample-ms must be at least 10".into());
    }
    let scenarios = ScenarioFile::load(&a.scenarios)?;
    let total = u32::try_from(scenarios.total_worktrees()).map_err(|e| e.to_string())?;
    if let Some(n) = a.worktrees
        && n != total
    {
        return Err(format!(
            "--worktrees is {n} but the scenarios use {total} worktrees"
        ));
    }
    let parent = a.scratch.clone().unwrap_or_else(|| {
        ctx.env
            .get_nonempty("TMPDIR")
            .map_or_else(|| PathBuf::from("/tmp"), PathBuf::from)
    });
    let parent = std::fs::canonicalize(&parent)
        .map_err(|e| format!("scratch dir {}: {e}", parent.display()))?;
    if !parent.is_dir() {
        return Err(format!("scratch dir {} is not a dir", parent.display()));
    }
    // The bench never writes into tollgate's own dirs.
    if let Ok(own) = Dirs::from_env(&ctx.env) {
        for d in [own.state_dir(), own.data_dir(), own.config_dir()] {
            let d = std::fs::canonicalize(&d).unwrap_or(d);
            if parent.starts_with(&d) {
                return Err(format!(
                    "scratch dir {} is inside tollgate's dir {}",
                    parent.display(),
                    d.display()
                ));
            }
        }
    }
    let plain = BenchEnv::new(&ctx.env, None, None);
    let repo_dir = ctx.cwd.join(&a.repo);
    let git = |args: &[&str]| {
        run_cmd(
            plain
                .command(Path::new("git"), &repo_dir)
                .args(args)
                .env("GIT_OPTIONAL_LOCKS", "0"),
            &format!("{}: git {}", repo_dir.display(), args.join(" ")),
        )
    };
    let common_dir = PathBuf::from(git(&[
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
    ])?);
    let common_dir = std::fs::canonicalize(&common_dir).unwrap_or(common_dir);
    let head = git(&["rev-parse", "--verify", "-q", "HEAD^{commit}"])
        .map_err(|_| format!("{}: HEAD is not a commit", repo_dir.display()))?;
    // The source repo is never written, not even by a scratch dir in it.
    let toplevel = git(&["rev-parse", "--show-toplevel"])
        .ok()
        .filter(|t| !t.is_empty())
        .map(|t| std::fs::canonicalize(&t).unwrap_or_else(|_| PathBuf::from(t)));
    if let Some(inside) = [Some(&common_dir), toplevel.as_ref()]
        .into_iter()
        .flatten()
        .find(|d| parent.starts_with(d))
    {
        return Err(format!(
            "scratch dir {} is inside the source repo {}",
            parent.display(),
            inside.display()
        ));
    }
    let mut host = match &a.base_config {
        Some(p) => {
            let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
            HostConfig::from_toml(&text).map_err(|e| format!("{}: {e}", p.display()))?
        }
        None => HostConfig::default(),
    };
    if let Some(m) = &a.min_free {
        host.verify.min_free = SizeSpec::parse(m).map_err(|e| format!("--min-free: {e}"))?;
    }
    for (name, slots) in [("cpu", a.cpu), ("pg", a.pg)] {
        if let Some(n) = slots {
            let key = ResourceName::parse(name).map_err(|e| e.to_string())?;
            let spec = match host.resources.remove(&key) {
                Some(ResourceSpec::Table { image, .. }) => ResourceSpec::Table { slots: n, image },
                _ => ResourceSpec::Slots(n),
            };
            host.resources.insert(key, spec);
        }
    }
    if let Some(t) = a.pg_max_threads {
        host.nextest.pg_max_threads = t;
    }
    Ok(Prepared {
        scenarios,
        worktrees: total,
        parent,
        common_dir,
        head,
        host,
    })
}

/// What the run collected while it went.
#[derive(Debug, Default)]
struct Run {
    resources: BTreeMap<String, u32>,
    warm: Option<Warm>,
    attempts: Vec<Attempt>,
    cpu: Vec<sample::CpuSample>,
    pg: Option<sample::PgSamples>,
}

/// `tollgate bench` (L20). Exit 0 when every commit got a gate decision,
/// 1 when one did not (out of scope, nothing to commit) or a signal
/// stopped the run, 2 when the bench could not run.
pub fn bench(ctx: &Ctx, a: &BenchArgs) -> u8 {
    let prep = match prepare(ctx, a) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("tollgate bench: {e}");
            return exit::BLOCK;
        }
    };
    trap_signals();
    let scratch = match Scratch::create(&prep.parent) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tollgate bench: {e}");
            return exit::BLOCK;
        }
    };
    let layout = Layout {
        root: scratch.path.clone(),
    };
    let env = BenchEnv::new(&ctx.env, Some(&layout), a.inline_cap);
    let dirs = match Dirs::from_env(&env.snapshot()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("tollgate bench: {e}");
            return exit::BLOCK;
        }
    };
    let mut run = Run::default();
    let result = execute(ctx, a, &prep, &layout, &env, &dirs, &mut run);
    let mut cleanup = cleanup_jobs(&dirs, &layout);
    let warm_job = run.warm.as_ref().and_then(|w| w.job.clone());
    let jobs = collect_jobs(&dirs, warm_job.as_deref());
    let scratch_removed = match scratch.finish(a.keep) {
        Ok(gone) => gone,
        Err(e) => {
            cleanup.error = Some(e);
            false
        }
    };
    if let Err(e) = result {
        eprintln!("tollgate bench: {e}");
        eprintln!(
            "tollgate bench: cleanup: {} job(s) cancelled, {} left{}",
            cleanup.cancelled.len(),
            cleanup.leftover.len(),
            cleanup
                .error
                .as_deref()
                .map(|e| format!("; {e}"))
                .unwrap_or_default()
        );
        return exit::BLOCK;
    }
    let report = BenchReport::build(Collected {
        repo: prep.common_dir,
        head: prep.head,
        scratch: layout.root.clone(),
        scratch_removed,
        worktrees: prep.worktrees,
        rounds: a.rounds,
        resources: run.resources,
        interrupted: stopped(),
        warm: run.warm,
        attempts: run.attempts,
        jobs,
        cpu: run.cpu,
        pg: run.pg,
        cleanup,
    });
    let json = match serde_json::to_string_pretty(&report) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("tollgate bench: {e}");
            return exit::BLOCK;
        }
    };
    let mut code = exit::OK;
    if let Some(out) = &a.out
        && let Err(e) = std::fs::write(out, format!("{json}\n"))
    {
        eprintln!("tollgate bench: {}: {e}", out.display());
        code = exit::BLOCK;
    }
    if a.json {
        println!("{json}");
    } else {
        for l in report.render() {
            println!("{l}");
        }
    }
    let ungated = report
        .attempts
        .iter()
        .filter(|a| matches!(a.outcome, HookOutcome::Ungated | HookOutcome::GitError))
        .count();
    if ungated > 0 {
        eprintln!(
            "tollgate bench: {ungated} commit(s) got no gate decision (ungated or git-error); the numbers do not measure the gate"
        );
        code = code.max(exit::FAIL);
    }
    if report.interrupted {
        code = code.max(exit::FAIL);
    }
    if a.enforce_budgets {
        let over: Vec<&str> = report
            .budgets
            .iter()
            .filter(|b| !b.ok)
            .map(|b| b.name.as_str())
            .collect();
        if !over.is_empty() {
            eprintln!("tollgate bench: L19 budget(s) over: {}", over.join(", "));
            code = code.max(exit::FAIL);
        }
    }
    code
}

/// Everything between making the scratch dir and cleanup.
fn execute(
    ctx: &Ctx,
    a: &BenchArgs,
    prep: &Prepared,
    layout: &Layout,
    env: &BenchEnv,
    dirs: &Dirs,
    run: &mut Run,
) -> Result<(), String> {
    install_hooks(&ctx.exe, layout)?;
    // R8: the hooks must use the bench's dirs, never an install's.
    let snap = env.snapshot();
    let hook_dirs = crate::hook::hook_dirs(&layout.hooks().join("pre-commit"), &snap)?;
    if &hook_dirs != dirs {
        return Err(format!(
            "the bench hooks would use the state dir {}, not {}",
            hook_dirs.state_dir().display(),
            dirs.state_dir().display()
        ));
    }
    let mut host = prep.host.clone();
    host.scope = ScopeConfig {
        roots: vec![
            layout
                .root
                .to_str()
                .ok_or("the scratch path is not UTF-8")?
                .to_owned(),
        ],
        remotes: Vec::new(),
        trusted_paths: Vec::new(),
        include: vec!["*".into()],
        exclude: Vec::new(),
    };
    // Item 38: jobs take CARGO_HOME and RUSTUP_HOME from the host config
    // only; the bench's caller's values stand in for a host config entry.
    for (key, slot) in [
        ("CARGO_HOME", &mut host.job.cargo_home),
        ("RUSTUP_HOME", &mut host.job.rustup_home),
    ] {
        if slot.is_none()
            && let Some(v) = ctx.env.get_nonempty(key).and_then(|v| v.to_str())
            && v.starts_with('/')
        {
            *slot = Some(v.to_owned());
        }
    }
    host.verify.root = Some(
        layout
            .root
            .join("verify")
            .to_str()
            .ok_or("the scratch path is not UTF-8")?
            .to_owned(),
    );
    let v = host.validate();
    if !v.is_ok() {
        let errs: Vec<String> = v.errors.iter().map(ToString::to_string).collect();
        return Err(format!("host config: {}", errs.join("; ")));
    }
    for name in ["cpu", "pg"] {
        let key = ResourceName::parse(name).map_err(|e| e.to_string())?;
        run.resources.insert(name.into(), host.resource_slots(&key));
    }
    run.resources
        .insert("pg_max_threads".into(), host.nextest.pg_max_threads);
    let text = toml::to_string(&host).map_err(|e| e.to_string())?;
    crate::fsx::write_atomic(&dirs.host_config_file(), text.as_bytes())
        .map_err(|e| format!("{}: {e}", dirs.host_config_file().display()))?;

    // The clone and its worktrees; no hook runs here.
    let no_hooks = layout.no_hooks();
    let clone = layout.clone_dir();
    run_cmd(
        env.git(&no_hooks, &layout.root)
            .args(["clone", "-q", "--shared", "--no-checkout"])
            .arg(&prep.common_dir)
            .arg(&clone),
        "git clone",
    )?;
    run_cmd(
        env.git(&no_hooks, &clone)
            .args(["fetch", "-q", "--update-head-ok"])
            .arg(&prep.common_dir)
            .arg("+refs/heads/*:refs/heads/*"),
        "git fetch of the local branches",
    )?;
    let assignment = prep.scenarios.assignment();
    for (i, sc) in (0u32..).zip(&assignment) {
        if stopped() {
            return Ok(());
        }
        run_cmd(
            env.git(&no_hooks, &clone)
                .args(["worktree", "add", "-q", "-b"])
                .arg(format!("tollgate-bench/{i}-{}", sc.name))
                .arg(layout.worktree(i))
                .arg(&prep.head),
            "git worktree add",
        )?;
    }
    if a.warm && !stopped() {
        run.warm = Some(warm(env, layout, &prep.head));
    }
    if stopped() {
        return Ok(());
    }
    let pg = a.pg_url.as_ref().map(|url| PgTarget {
        psql: a.psql.clone(),
        url: url.clone(),
        env: env.psql(&ctx.env),
    });
    let samplers = Samplers::start(Duration::from_millis(a.sample_ms), pg);
    let worker = Worker {
        env,
        layout,
        keep: a.keep,
        t0: Instant::now(),
        rounds: a.rounds,
        barrier: Barrier::new(assignment.len()),
    };
    let attempts: Vec<Attempt> = std::thread::scope(|s| {
        let handles: Vec<_> = (0u32..)
            .zip(&assignment)
            .map(|(i, sc)| {
                let w = &worker;
                s.spawn(move || w.run(i, sc))
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    let (cpu, pg) = samplers.finish();
    run.attempts = attempts;
    run.cpu = cpu;
    run.pg = pg;
    Ok(())
}

/// `bin/tollgate` and its hook links in the scratch dir.
fn install_hooks(exe: &Path, layout: &Layout) -> Result<(), String> {
    fn io(p: &Path) -> impl FnOnce(std::io::Error) -> String + '_ {
        move |e| format!("{}: {e}", p.display())
    }
    let bin = layout.bin();
    for d in [
        bin.parent().unwrap_or(&layout.root),
        &layout.hooks(),
        &layout.no_hooks(),
        &layout.root.join("trace"),
    ] {
        crate::fsx::ensure_dir(d).map_err(io(d))?;
    }
    // A binary replaced while it runs is still `/proc/self/exe`.
    let src = if exe.is_file() {
        exe
    } else {
        Path::new("/proc/self/exe")
    };
    std::fs::hard_link(src, &bin)
        .or_else(|_| std::fs::copy(src, &bin).map(|_| ()))
        .map_err(io(&bin))?;
    for name in crate::hook::installed_hook_names() {
        let link = layout.hooks().join(name);
        std::fs::hard_link(&bin, &link).map_err(io(&link))?;
    }
    Ok(())
}

/// `tollgate check` of the start commit in the clone, waiting for its
/// job.
fn warm(env: &BenchEnv, layout: &Layout, head: &str) -> Warm {
    let start = Instant::now();
    let out = run_stoppable(
        env.command(&layout.bin(), &layout.clone_dir())
            .args(["check", "--tier", "fast", "--rev", head, "--wait"]),
        &layout.trace("warm"),
        SLOW_POLL,
    );
    let elapsed = ms(start.elapsed());
    match out {
        Ok(o) => {
            let text = format!("{}{}", o.stdout, o.stderr);
            Warm {
                exit: o.status.code(),
                ms: elapsed,
                job: text
                    .split_whitespace()
                    .skip_while(|w| *w != "job")
                    .nth(1)
                    .map(str::to_owned),
            }
        }
        Err(_) => Warm {
            exit: None,
            ms: elapsed,
            job: None,
        },
    }
}

/// One worktree's thread.
struct Worker<'a> {
    env: &'a BenchEnv,
    layout: &'a Layout,
    keep: bool,
    t0: Instant,
    rounds: u32,
    barrier: Barrier,
}

impl Worker<'_> {
    fn run(&self, i: u32, sc: &Scenario) -> Vec<Attempt> {
        let mut out = Vec::new();
        for round in 0..self.rounds {
            let ready = if stopped() {
                Err("interrupted".to_owned())
            } else {
                self.edit(i, sc, round)
            };
            // Every worktree starts its commit together.
            self.barrier.wait();
            if let Err(e) = ready {
                if !stopped() {
                    out.push(self.failed(i, sc, round, e));
                }
                continue;
            }
            if stopped() {
                continue;
            }
            let msg = format!("bench {} worktree {i} round {round}", sc.name);
            let first = self.commit(i, sc, round, 0, &["commit", "-q", "-m", &msg], None);
            let mut last = first.clone();
            out.push(first);
            for k in 1..=sc.retries {
                if stopped() {
                    break;
                }
                let (args, wait_ms): (Vec<&str>, Option<f64>) = if last.exit == Some(0) {
                    (vec!["commit", "-q", "--amend", "--no-edit"], None)
                } else {
                    // L17: wait for the job, then the same command.
                    let wait_ms = match (&last.outcome, &last.job) {
                        (HookOutcome::Running, Some(job)) => Some(self.wait(i, job)),
                        _ => None,
                    };
                    (vec!["commit", "-q", "-m", &msg], wait_ms)
                };
                let mut next = self.commit(i, sc, round, k, &args, wait_ms);
                next.kind = AttemptKind::Retry;
                last = next.clone();
                out.push(next);
            }
        }
        out
    }

    /// Applies the scenario's edits and stages them.
    fn edit(&self, i: u32, sc: &Scenario, round: u32) -> Result<(), String> {
        let wt = self.layout.worktree(i);
        let at = Place {
            worktree: i,
            round,
            scenario: &sc.name,
        };
        for e in &sc.edit {
            e.apply(&wt, at)
                .map_err(|x| format!("edit {}: {x}", e.path))?;
        }
        run_cmd(
            self.env
                .git(&self.layout.no_hooks(), &wt)
                .arg("add")
                .arg("--")
                .args(sc.edit.iter().map(|e| e.path.as_str())),
            "git add",
        )
        .map(|_| ())
    }

    fn failed(&self, i: u32, sc: &Scenario, round: u32, message: String) -> Attempt {
        Attempt {
            worktree: i,
            scenario: sc.name.clone(),
            round,
            kind: AttemptKind::Commit,
            start_ms: ms(self.t0.elapsed()),
            exit: None,
            outcome: HookOutcome::GitError,
            job: None,
            docs_only: false,
            hook_ms: None,
            wall_ms: 0.0,
            hooks: BTreeMap::new(),
            wait_ms: None,
            message: Some(message),
        }
    }

    /// `tollgate wait <job>`; its duration.
    fn wait(&self, i: u32, job: &str) -> f64 {
        let start = Instant::now();
        let _ = run_stoppable(
            self.env
                .command(&self.layout.bin(), &self.layout.worktree(i))
                .args(["wait", job]),
            &self.layout.trace(&format!("w{i}-wait")),
            SLOW_POLL,
        );
        ms(start.elapsed())
    }

    /// One traced `git commit`.
    fn commit(
        &self,
        i: u32,
        sc: &Scenario,
        round: u32,
        k: u32,
        args: &[&str],
        wait_ms: Option<f64>,
    ) -> Attempt {
        let wt = self.layout.worktree(i);
        let trace = self.layout.trace(&format!("w{i}-r{round}-{k}"));
        let start_ms = ms(self.t0.elapsed());
        let start = Instant::now();
        let out = run_stoppable(
            self.env.commit(self.layout, &wt, &trace).args(args),
            &trace,
            COMMIT_POLL,
        );
        let wall_ms = ms(start.elapsed());
        let text = std::fs::read_to_string(&trace).unwrap_or_default();
        if !self.keep {
            let _ = std::fs::remove_file(&trace);
        }
        let hooks: BTreeMap<String, f64> = trace::hook_times(&text)
            .into_iter()
            .map(|h| (h.hook, round_ms(h.ms)))
            .collect();
        let (exit, outcome, job, message) = match out {
            Ok(o) => {
                let (outcome, job, message) = classify(o.status.success(), &o.stderr);
                (o.status.code(), outcome, job, message)
            }
            Err(e) => (None, HookOutcome::GitError, None, Some(e.to_string())),
        };
        Attempt {
            worktree: i,
            scenario: sc.name.clone(),
            round,
            kind: AttemptKind::Commit,
            start_ms,
            exit,
            outcome,
            job,
            docs_only: false,
            hook_ms: hooks.get("pre-commit").copied(),
            wall_ms,
            hooks,
            wait_ms,
            message,
        }
    }
}

/// Cancels the jobs that still run, waits for every runner to exit, and
/// kills what is left (Linux: every process whose environment names the
/// bench's state dir).
fn cleanup_jobs(dirs: &Dirs, layout: &Layout) -> Cleanup {
    let store = JobStore::new(dirs);
    let all = store.list().unwrap_or_default();
    let open: Vec<JobId> = all
        .iter()
        .filter(|m| !m.state.is_terminal())
        .map(|m| m.id.clone())
        .collect();
    let mut c = Cleanup::default();
    for id in &open {
        if store.request_cancel(id).is_ok() {
            c.cancelled.push(id.to_string());
        }
    }
    let still_open = || -> Vec<JobId> {
        open.iter()
            .filter(|id| store.read(id).is_ok_and(|m| !m.state.is_terminal()))
            .cloned()
            .collect()
    };
    // A runner holds its job's key lock until it exits (R88).
    let runner_alive = || {
        all.iter().any(|m| {
            crate::sched::running_job(dirs, &m.key)
                .ok()
                .flatten()
                .is_some_and(|id| id == m.id)
        })
    };
    let end = Instant::now() + CANCEL_WAIT;
    while Instant::now() < end && (!still_open().is_empty() || runner_alive()) {
        for id in still_open() {
            let _ = crate::sched::reap_if_lost(dirs, &id);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut marker = b"XDG_STATE_HOME=".to_vec();
    marker.extend_from_slice(layout.state_home().as_os_str().as_encoded_bytes());
    c.killed = crate::procs::kill_marked(&marker, Duration::from_secs(5)).0;
    for id in still_open() {
        let _ = crate::sched::reap_if_lost(dirs, &id);
    }
    c.leftover = still_open().iter().map(ToString::to_string).collect();
    c
}

fn collect_jobs(dirs: &Dirs, warm_job: Option<&str>) -> Vec<JobRow> {
    JobStore::new(dirs)
        .list()
        .unwrap_or_default()
        .iter()
        .map(|m| {
            let r = JobReport::read(dirs, &m.id).ok().flatten();
            JobRow::new(m, r.as_ref(), warm_job == Some(m.id.as_str()))
        })
        .collect()
}
