//! tollgate binary: panic guard, argv\[0\] hook dispatch, CLI, exit codes.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use tollgate::config::Tier;
use tollgate::{cli, exit};

fn main() -> ExitCode {
    // R23: a panic exits 2, never 101.
    let code = std::panic::catch_unwind(run).unwrap_or(exit::PANIC);
    ExitCode::from(code)
}

fn run() -> u8 {
    let args: Vec<OsString> = std::env::args_os().collect();
    // R1: a hard link named after a hook dispatches on argv[0].
    if let Some(name) = args
        .first()
        .and_then(|a0| tollgate::hook::dispatch_name(a0))
    {
        return hook_main(name, &args[1..]);
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                exit::BLOCK
            } else {
                exit::OK
            };
        }
    };
    let ctx = match std::env::current_dir() {
        Ok(cwd) => cli::Ctx {
            env: tollgate::env::EnvSnapshot::capture(),
            cwd,
            exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("tollgate")),
        },
        Err(e) => {
            eprintln!("tollgate: cannot read the current dir: {e}");
            return exit::BLOCK;
        }
    };
    // Item 39: git by the absolute path install recorded.
    tollgate::gitx::init_program(&ctx.exe, &ctx.env);
    match cli.command {
        Command::Hook { name, args } => match tollgate::hook::hook_name(&name) {
            Some(name) => hook_main(name, &args),
            None => {
                eprintln!("tollgate: unknown hook {name:?}");
                exit::BLOCK
            }
        },
        Command::Config(c) => config_main(&ctx, &c),
        Command::Check {
            tier,
            tree,
            rev,
            wait,
            detach,
            rerun,
            all,
        } => cli::check(
            &ctx,
            &cli::CheckArgs {
                tier: tier.map_or(Tier::Fast, TierArg::tier),
                tree,
                rev,
                wait,
                detach,
                rerun,
                all,
            },
        ),
        Command::Wait { job, timeout } => cli::wait(&ctx, &job, timeout.as_deref()),
        Command::Cancel { job } => cli::cancel(&ctx, &job),
        Command::Status { rev, json } => cli::status(&ctx, rev.as_deref(), json),
        Command::Report { target, json } => cli::report_cmd(&ctx, &target, json),
        Command::Log { job, step, tail } => cli::log(&ctx, &job, &step, tail),
        Command::Run {
            step,
            tier,
            here: _,
            report,
            no_host_locks,
            rev,
            tree,
            rerun,
            wait,
            detach,
            args,
        } => match (step, tier) {
            (Some(step), _) => cli::run_step(
                &ctx,
                &cli::StepArgs {
                    step,
                    rev,
                    tree,
                    rerun,
                    wait,
                    detach,
                    args,
                },
            ),
            (None, Some(tier)) => cli::run_here(
                &ctx,
                cli::HereArgs {
                    tier: tier.tier(),
                    junit: report.is_some(),
                    no_host_locks,
                },
            ),
            // clap requires a step or --here, and --here requires --tier.
            (None, None) => tollgate::exit::BLOCK,
        },
        Command::Gc { all } => cli::gc(&ctx, all),
        Command::Audit { since } => cli::audit(&ctx, since.as_deref()),
        Command::Flaky { days } => cli::flaky(&ctx, days),
        Command::Stats { since, json } => cli::stats(&ctx, since.as_deref(), json),
        Command::Cost { since, repo, json } => cli::cost(&ctx, &since, repo.as_deref(), json),
        Command::RunJob { job, lock_fd } => cli::run_job(&ctx, &job, lock_fd),
        Command::Merge { branch } => tollgate::merge::merge(&ctx, &branch),
        Command::Remotes {
            action: RemotesAction::Forget { repo },
        } => cli::remotes_forget(&ctx, repo.as_deref()),
        Command::Install => tollgate::install::install(&ctx),
        Command::Uninstall => tollgate::install::uninstall(&ctx),
        Command::Doctor { repo, injection } => tollgate::install::doctor::doctor(
            &ctx,
            &tollgate::install::doctor::Options { repo, injection },
        ),
        Command::Guard => guard_main(&ctx),
        Command::Step {
            kind,
            findings,
            root,
            baseline,
        } => tollgate::steps::baseline::step(kind.kind(), baseline.as_deref(), &findings, &root),
        Command::Baseline {
            action: BaselineAction::Record { kind, force },
        } => tollgate::steps::baseline::record_cmd(&ctx.env, &ctx.cwd, kind.kind(), force),
        Command::CiSnippet { gitlab: _ } => tollgate::ci::ci_snippet_cmd(),
        Command::Bench(b) => tollgate::bench::bench(&ctx, &b.args()),
    }
}

/// Runs a gate or chained hook (R1, R7, R17, R20). R31: a hook that cannot
/// even read its cwd denies.
fn hook_main(name: &'static str, args: &[OsString]) -> u8 {
    let started = std::time::Instant::now();
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tollgate: DENIED {name}: cannot read the current dir: {e}");
            return exit::FAIL;
        }
    };
    tollgate::hook::run(
        name,
        args,
        &tollgate::hook::HookCtx {
            env: tollgate::env::EnvSnapshot::capture(),
            cwd,
            exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("tollgate")),
            started,
        },
    )
}

/// The PreToolUse guard (R23): stdin JSON in, exit 0 or 2.
fn guard_main(ctx: &cli::Ctx) -> u8 {
    use std::io::{Read as _, Write as _};
    // R23 test hook: a forced panic must block (exit 2). It can only make
    // the guard deny more, never allow.
    if ctx.env.get_str("TOLLGATE_TEST_PANIC") == Some("guard") {
        panic!("forced guard panic (TOLLGATE_TEST_PANIC)");
    }
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("tollgate guard: cannot read stdin: {e}");
        return exit::BLOCK;
    }
    let a = tollgate::guard::guard(&ctx.env, &input, &ctx.exe, &ctx.cwd);
    if !a.stdout.is_empty() {
        let _ = writeln!(std::io::stdout(), "{}", a.stdout);
    }
    if !a.stderr.is_empty() {
        eprintln!("{}", a.stderr);
    }
    if a.code == exit::OK {
        exit::OK
    } else {
        exit::BLOCK
    }
}

fn config_main(ctx: &cli::Ctx, args: &ConfigArgs) -> u8 {
    if args.check {
        let report = tollgate::config::check::check(&ctx.cwd, &ctx.env);
        for line in &report.lines {
            println!("{line}");
        }
        return if report.ok { exit::OK } else { exit::FAIL };
    }
    if args.effective {
        return cli::config_effective(ctx);
    }
    match &args.action {
        Some(ConfigAction::Init { nextest }) => cli::config_init(ctx, *nextest),
        None => {
            eprintln!("tollgate config: use --effective, --check or init");
            exit::BLOCK
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "tollgate",
    version,
    about = "Gate git ref updates on checks of the exact tree"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum TierArg {
    Fast,
    Full,
}

impl TierArg {
    fn tier(self) -> Tier {
        match self {
            Self::Fast => Tier::Fast,
            Self::Full => Tier::Full,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Junit,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BaselineKind {
    Pyright,
    Pytest,
}

impl BaselineKind {
    fn kind(self) -> tollgate::steps::baseline::Kind {
        match self {
            Self::Pyright => tollgate::steps::baseline::Kind::Pyright,
            Self::Pytest => tollgate::steps::baseline::Kind::Pytest,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BaselineStep {
    PyrightBaseline,
    PytestBaseline,
}

impl BaselineStep {
    fn kind(self) -> tollgate::steps::baseline::Kind {
        match self {
            Self::PyrightBaseline => tollgate::steps::baseline::Kind::Pyright,
            Self::PytestBaseline => tollgate::steps::baseline::Kind::Pytest,
        }
    }
}

/// L14: the v1 CLI subset. `pick`, `policy approve` and `waive` are CUT.
#[derive(Debug, Subcommand)]
enum Command {
    /// Copy the binary, link the hooks, add the settings entries (R95).
    /// At an interactive terminal only; asks before the settings change
    /// (L10, item 29).
    Install,
    /// Remove exactly what install added (R96). At an interactive
    /// terminal only (L10, item 29).
    Uninstall,
    /// Check the installation, injection, tools, disk and locks (R97).
    Doctor {
        #[arg(long)]
        repo: Option<PathBuf>,
        #[arg(long)]
        injection: bool,
    },
    /// Run or pre-warm a tier on a tree (R99).
    Check {
        #[arg(long, value_enum)]
        tier: Option<TierArg>,
        #[arg(long, conflicts_with = "rev")]
        tree: Option<String>,
        #[arg(long)]
        rev: Option<String>,
        #[arg(long, conflicts_with = "detach")]
        wait: bool,
        #[arg(long)]
        detach: bool,
        /// Drop the stored result and run the steps that did not pass
        /// on this tree (R101).
        #[arg(long)]
        rerun: bool,
        /// With --rerun: run every step again.
        #[arg(long, requires = "rerun")]
        all: bool,
    },
    /// Wait for a job (exit 0 pass, 1 fail, 3 running) (R99).
    Wait {
        job: String,
        #[arg(long)]
        timeout: Option<String>,
    },
    /// Cancel a queued or running job (R89).
    Cancel { job: String },
    /// Records, running jobs and policy state for HEAD and the index (R92, L1).
    Status {
        #[arg(long)]
        rev: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Print a job or tree report (R92).
    Report {
        target: String,
        #[arg(long)]
        json: bool,
    },
    /// Print a step log (R92).
    Log {
        job: String,
        step: String,
        #[arg(long)]
        tail: Option<usize>,
    },
    /// Run one declared step (R105), or, with --here, the CI mode: every
    /// step in the current directory (R47).
    Run {
        /// The step to run (R105).
        #[arg(required_unless_present = "here", conflicts_with = "here")]
        step: Option<String>,
        #[arg(long, value_enum, requires = "here")]
        tier: Option<TierArg>,
        #[arg(long, requires = "tier")]
        here: bool,
        #[arg(long, value_enum, requires = "here")]
        report: Option<ReportFormat>,
        #[arg(long, requires = "here")]
        no_host_locks: bool,
        #[arg(long, conflicts_with_all = ["tree", "here"])]
        rev: Option<String>,
        #[arg(long, conflicts_with = "here")]
        tree: Option<String>,
        /// Run the step even when a stored pass answers.
        #[arg(long, conflicts_with = "here")]
        rerun: bool,
        #[arg(long, conflicts_with_all = ["detach", "here"])]
        wait: bool,
        #[arg(long, conflicts_with = "here")]
        detach: bool,
        /// Arguments that narrow the step, after `--`.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Merge with a full check before the commit (R99).
    Merge { branch: String },
    /// Show, check or write the repo config (R64, R65).
    Config(ConfigArgs),
    /// Print a CI job that runs the full tier (R73).
    CiSnippet {
        #[arg(long, required = true)]
        gitlab: bool,
    },
    /// The recorded trusted remotes of a repo (item 33).
    Remotes {
        #[command(subcommand)]
        action: RemotesAction,
    },
    /// Record a Python baseline (TTY only) (R94).
    Baseline {
        #[command(subcommand)]
        action: BaselineAction,
    },
    /// Flaky test counts (R93).
    Flaky {
        #[arg(long, default_value_t = 14)]
        days: u32,
    },
    /// How much time the gate costs: hook outcomes, job and queue times,
    /// guard decisions by rule (item 50).
    Stats {
        /// Only events after this: a date `YYYY-MM-DD`, `<n>d` or a
        /// duration (`12h`).
        #[arg(long)]
        since: Option<String>,
        /// JSON instead of the table.
        #[arg(long)]
        json: bool,
    },
    /// Gate time per repo and local day, and the branches that cost most
    /// (R109). Read-only.
    Cost {
        /// Only jobs after this: a date `YYYY-MM-DD`, `<n>d` or a duration
        /// (`12h`). Default `7d`.
        #[arg(long, default_value = "7d")]
        since: String,
        /// Only this repo (its name in the metrics log).
        #[arg(long)]
        repo: Option<String>,
        /// JSON instead of the tables.
        #[arg(long)]
        json: bool,
    },
    /// List records for review (R83).
    Audit {
        #[arg(long)]
        since: Option<String>,
    },
    /// Remove old records, logs and checkouts (R48).
    Gc {
        #[arg(long)]
        all: bool,
    },
    /// PreToolUse entry point; reads hook JSON on stdin (R23).
    Guard,
    /// Dev: replay concurrent commits from N worktrees through the real
    /// hooks and report latency, queue wait, load and reuse (L20).
    Bench(BenchCmd),
    /// Run a hook by name (same as the hook link).
    Hook {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Internal: the detached job runner (R38).
    #[command(name = "__run-job", hide = true)]
    RunJob {
        job: String,
        #[arg(long)]
        lock_fd: Option<i32>,
    },
    /// Internal: a Python baseline step in a job (R94).
    #[command(name = "__step", hide = true)]
    Step {
        #[arg(value_enum)]
        kind: BaselineStep,
        #[arg(long)]
        findings: PathBuf,
        #[arg(long, default_value = ".")]
        root: String,
        #[arg(long)]
        baseline: Option<PathBuf>,
    },
}

/// `tollgate bench` (L20). The source repo is never written: the bench
/// clones it into its own scratch dir, with its own state and host config.
#[derive(Debug, Args)]
struct BenchCmd {
    /// The repo to replay commits on (any dir in it).
    repo: PathBuf,
    /// TOML file of `[[scenario]]` tables: name, worktrees, retries, edit.
    #[arg(long)]
    scenarios: PathBuf,
    /// N, the number of worktrees; must equal the scenarios' total.
    #[arg(long, short = 'n')]
    worktrees: Option<u32>,
    /// Commits per worktree (each round edits and commits again).
    #[arg(long, default_value_t = 1)]
    rounds: u32,
    /// Parent dir of the scratch dir (default `$TMPDIR`). Verify
    /// checkouts and build output go there.
    #[arg(long)]
    scratch: Option<PathBuf>,
    /// Keep the scratch dir for inspection.
    #[arg(long)]
    keep: bool,
    /// `cpu` resource slots.
    #[arg(long)]
    cpu: Option<u32>,
    /// `pg` resource slots.
    #[arg(long)]
    pg: Option<u32>,
    /// `nextest.pg_max_threads`.
    #[arg(long)]
    pg_max_threads: Option<u32>,
    /// Host config to start from (job env, nextest, budgets); scope and
    /// verify root are always the bench's.
    #[arg(long)]
    base_config: Option<PathBuf>,
    /// `verify.min_free` (default: the base config's, else 30G).
    #[arg(long)]
    min_free: Option<String>,
    /// `TOLLGATE_INLINE_CAP` of the commits, in seconds.
    #[arg(long)]
    inline_cap: Option<u64>,
    /// Postgres URL whose connections to sample with psql.
    #[arg(long)]
    pg_url: Option<String>,
    /// The psql program.
    #[arg(long, default_value = "psql")]
    psql: PathBuf,
    /// Sample interval of CPU load and Postgres, in milliseconds.
    #[arg(long, default_value_t = 250)]
    sample_ms: u64,
    /// Skip the warm-up check of the start commit.
    #[arg(long)]
    no_warm: bool,
    /// Print JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Also write the JSON report to this file.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Exit 1 when a measured L19 budget is over (wall-clock p95).
    #[arg(long)]
    enforce_budgets: bool,
}

impl BenchCmd {
    fn args(&self) -> tollgate::bench::BenchArgs {
        tollgate::bench::BenchArgs {
            repo: self.repo.clone(),
            scenarios: self.scenarios.clone(),
            worktrees: self.worktrees,
            rounds: self.rounds,
            scratch: self.scratch.clone(),
            keep: self.keep,
            cpu: self.cpu,
            pg: self.pg,
            pg_max_threads: self.pg_max_threads,
            base_config: self.base_config.clone(),
            min_free: self.min_free.clone(),
            inline_cap: self.inline_cap,
            pg_url: self.pg_url.clone(),
            psql: self.psql.clone(),
            sample_ms: self.sample_ms,
            warm: !self.no_warm,
            json: self.json,
            out: self.out.clone(),
            enforce_budgets: self.enforce_budgets,
        }
    }
}

#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
struct ConfigArgs {
    /// Print the effective config (repo file or detection).
    #[arg(long, conflicts_with = "check")]
    effective: bool,
    /// Validate the working tree's tollgate.toml and the host config.
    #[arg(long)]
    check: bool,
    #[command(subcommand)]
    action: Option<ConfigAction>,
}

#[derive(Debug, Subcommand)]
enum ConfigAction {
    /// Write the detected config for review.
    Init {
        #[arg(long)]
        nextest: bool,
    },
}

#[derive(Debug, Subcommand)]
enum RemotesAction {
    /// Forget the trusted remotes recorded for a repo, accepting that one
    /// is gone (TTY only).
    Forget {
        /// The repo (default: the current dir).
        repo: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum BaselineAction {
    Record {
        #[arg(value_enum)]
        kind: BaselineKind,
        #[arg(long)]
        force: bool,
    },
}
