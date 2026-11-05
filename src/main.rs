//! tollgate binary: panic guard, argv\[0\] hook dispatch, CLI, exit codes.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use tollgate::exit;

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
    match cli.command {
        Command::Hook { name, args } => match tollgate::hook::hook_name(&name) {
            Some(name) => hook_main(name, &args),
            None => {
                eprintln!("tollgate: unknown hook {name:?}");
                exit::BLOCK
            }
        },
        Command::Config(c) => config_main(&c),
        other => not_built(other.name()),
    }
}

/// Gate and chained hooks are built in a later phase. Until then a hook
/// denies (R31: every exit path is an explicit decision; fail closed).
fn hook_main(name: &str, _args: &[OsString]) -> u8 {
    eprintln!("tollgate: DENIED {name}: hook handling is not built yet");
    exit::FAIL
}

fn config_main(args: &ConfigArgs) -> u8 {
    let what = if args.check {
        "config --check"
    } else if args.effective {
        "config --effective"
    } else {
        "config init"
    };
    not_built(what)
}

fn not_built(what: &str) -> u8 {
    eprintln!("tollgate {what}: not built yet");
    exit::BLOCK
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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReportFormat {
    Junit,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum BaselineKind {
    Pyright,
    Pytest,
}

/// L14: the v1 CLI subset. `pick`, `policy approve` and `waive` are CUT.
#[derive(Debug, Subcommand)]
enum Command {
    /// Copy the binary, link the hooks, add the settings entries (R95).
    Install {
        #[arg(long)]
        yes: bool,
    },
    /// Remove exactly what install added (R96).
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
        #[arg(long)]
        rerun: bool,
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
    /// CI mode: run the steps in the current directory (R47).
    Run {
        #[arg(long, value_enum)]
        tier: TierArg,
        #[arg(long, required = true)]
        here: bool,
        #[arg(long, value_enum)]
        report: Option<ReportFormat>,
        #[arg(long)]
        no_host_locks: bool,
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
    /// Run a hook by name (same as the hook link).
    Hook {
        name: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

impl Command {
    fn name(&self) -> &'static str {
        match self {
            Self::Install { .. } => "install",
            Self::Uninstall => "uninstall",
            Self::Doctor { .. } => "doctor",
            Self::Check { .. } => "check",
            Self::Wait { .. } => "wait",
            Self::Cancel { .. } => "cancel",
            Self::Status { .. } => "status",
            Self::Report { .. } => "report",
            Self::Log { .. } => "log",
            Self::Run { .. } => "run",
            Self::Merge { .. } => "merge",
            Self::Config(_) => "config",
            Self::CiSnippet { .. } => "ci-snippet",
            Self::Baseline { .. } => "baseline",
            Self::Flaky { .. } => "flaky",
            Self::Audit { .. } => "audit",
            Self::Gc { .. } => "gc",
            Self::Guard => "guard",
            Self::Hook { .. } => "hook",
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
enum BaselineAction {
    Record {
        #[arg(value_enum)]
        kind: BaselineKind,
        #[arg(long)]
        force: bool,
    },
}
