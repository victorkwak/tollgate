//! Runners (G2, item 40, review notes 11 and 1): programs that run the
//! command in their arguments with the session's environment, but may
//! change what that command finds or how it runs: tracers (`strace`,
//! `ltrace`, `valgrind`, `perf stat|record|trace`, `catchsegv`), output
//! and session helpers (`chronic`, `xvfb-run`, `systemd-inhibit`,
//! `systemd-cat`) and package runners, which put a project's tool dir
//! first on `PATH` (`uv run`, `uvx`, `npx`, `npm exec`, `pnpm exec|dlx`,
//! `yarn exec|dlx`, `bunx`, `bun x`).
//!
//! The command is found by each runner's option grammar and walked as if
//! typed, except that git, tollgate and shells may not run under a runner
//! at any depth: the runner may find another program by those names, or
//! trace or detach them. An option the grammar does not list makes the
//! guard hold every word to the launcher rule instead (no git, tollgate,
//! shell or interpreter, all literal), so a missing table entry costs a
//! deny, never a pass. `cargo run` of tollgate's own repo runs tollgate:
//! its person-only subcommands deny there too.

use super::cmds::{self, Opt, Opts, parse_opts};

/// What a runner does with its words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// The command is `argv[at..]`, with `prefix` put in front of it
    /// (`uv run -m mod` runs `python -m mod`). `moved` is true when the
    /// runner changes the cwd first (`--directory`, `--cwd`).
    Walk {
        at: usize,
        prefix: &'static [&'static str],
        moved: bool,
    },
    /// The command was not found: `argv[from..]` are held to the
    /// launcher rule.
    Strict {
        from: usize,
    },
    Deny(String),
}

const NONE: Opts = Opts {
    short_flags: "",
    short_val: "",
    short_opt: "",
    long_flags: &[],
    long_val: &[],
    long_opt: &[],
};

/// Names [`launch`] may answer for (a quick test on the hot path).
const NAMES: &[&str] = &[
    "strace",
    "ltrace",
    "valgrind",
    "perf",
    "catchsegv",
    "chronic",
    "xvfb-run",
    "systemd-inhibit",
    "systemd-cat",
    "uv",
    "uvx",
    "npx",
    "npm",
    "pnpm",
    "pnpx",
    "yarn",
    "bunx",
    "bun",
    "cargo",
];

/// True when `base` is a runner (its run forms) or `cargo`.
#[must_use]
pub fn is_runner(base: &str) -> bool {
    NAMES.contains(&base)
}

/// What runner `base` does with `lits` (`lits[0]` is its name); `None`
/// when this use runs no command (`uv pip`, `npm install`, `cargo build`).
#[must_use]
pub fn launch(base: &str, lits: &[Option<String>]) -> Option<Launch> {
    match base {
        "strace" => Some(walk(&STRACE, lits, 1)),
        "ltrace" => Some(walk(&LTRACE, lits, 1)),
        "valgrind" => Some(valgrind(lits)),
        "catchsegv" => Some(walk(&NONE, lits, 1)),
        "chronic" => Some(walk(&CHRONIC, lits, 1)),
        "xvfb-run" => Some(walk(&XVFB_RUN, lits, 1)),
        "systemd-inhibit" => Some(walk(&SYSTEMD_INHIBIT, lits, 1)),
        "systemd-cat" => Some(walk(&SYSTEMD_CAT, lits, 1)),
        "perf" => match lits.get(1).cloned().flatten().as_deref() {
            Some("stat" | "record" | "trace") => Some(walk(&PERF, lits, 2)),
            Some(s) if s.starts_with('-') => Some(Launch::Strict { from: 1 }),
            // Other subcommands that take a command (`sched record`,
            // `mem record`, `ftrace`, `script`) are not parsed.
            _ => Some(Launch::Strict { from: 1 }),
        },
        "uv" => uv(lits),
        "uvx" => Some(walk(&UVX, lits, 1)),
        "npx" => Some(walk(&NPX, lits, 1)),
        "bunx" => Some(walk(&BUNX, lits, 1)),
        "pnpx" => Some(walk(&PNPM_DLX, lits, 1)),
        "npm" => sub_runner(lits, &[("exec", &NPX), ("x", &NPX)]),
        "pnpm" => sub_runner(lits, &[("exec", &PNPM_EXEC), ("dlx", &PNPM_DLX)]),
        "yarn" => sub_runner(lits, &[("exec", &NONE), ("dlx", &YARN_DLX)]),
        "bun" => bun(lits),
        "cargo" => cargo(lits),
        _ => None,
    }
}

/// The command after `spec`'s options from `lits[start..]`.
fn walk(spec: &Opts, lits: &[Option<String>], start: usize) -> Launch {
    walk_after(spec, lits, start, &[])
}

/// [`walk`], with `earlier` options of the program (uv's global ones)
/// counting as the runner's own.
fn walk_after(spec: &Opts, lits: &[Option<String>], start: usize, earlier: &[Opt]) -> Launch {
    let Ok((opts, at)) = parse_opts(spec, lits, start) else {
        return Launch::Strict { from: start };
    };
    let mut prefix: &'static [&'static str] = &[];
    let mut moved = false;
    for o in earlier.iter().chain(&opts) {
        match o.name.as_str() {
            // Variables from a file, or set for the command: the guard
            // reads neither (G5).
            "--env-file" | "-E" | "--env" => {
                return Launch::Deny(format!(
                    "{} {}: sets variables for the command that the guard does not check (G2, G5)",
                    lits[0].as_deref().unwrap_or_default(),
                    o.name
                ));
            }
            // Code in a shell string.
            "--call" | "--shell-mode" => return Launch::Strict { from: start },
            "-c" if (spec.short_val.contains('c') && spec.long_val.contains(&"call"))
                || spec.long_flags.contains(&"shell-mode") =>
            {
                return Launch::Strict { from: start };
            }
            "-m" | "--module" if spec.long_flags.contains(&"module") => prefix = &["python", "-m"],
            "-s" | "--script" | "--gui-script" if spec.long_flags.contains(&"script") => {
                prefix = &["python"];
            }
            "--directory" | "--cwd" => moved = true,
            _ => {}
        }
    }
    Launch::Walk { at, prefix, moved }
}

/// `valgrind [--opt[=v]]... [-q|-v] PROG ARGS`: its options never take a
/// separate value.
fn valgrind(lits: &[Option<String>]) -> Launch {
    let mut i = 1;
    while let Some(w) = lits.get(i) {
        let Some(a) = w.as_deref() else {
            return Launch::Strict { from: 1 };
        };
        if a == "--" {
            i += 1;
            break;
        }
        if a.starts_with("--") || matches!(a, "-q" | "-v" | "-h" | "-d") {
            i += 1;
            continue;
        }
        if a.starts_with('-') {
            return Launch::Strict { from: 1 };
        }
        break;
    }
    Launch::Walk {
        at: i,
        prefix: &[],
        moved: false,
    }
}

/// `uv [opts] run [opts] CMD` and `uv [opts] tool run [opts] CMD`.
fn uv(lits: &[Option<String>]) -> Option<Launch> {
    let Ok((global, k)) = parse_opts(&UV_RUN, lits, 1) else {
        // Global options the grammar does not know: any subcommand.
        return Some(Launch::Strict { from: 1 });
    };
    match lits.get(k).cloned().flatten().as_deref() {
        Some("run") => Some(walk_after(&UV_RUN, lits, k + 1, &global)),
        Some("tool") if lits.get(k + 1).cloned().flatten().as_deref() == Some("run") => {
            Some(walk_after(&UVX, lits, k + 2, &global))
        }
        Some(_) => None,
        None if k < lits.len() => Some(Launch::Strict { from: 1 }),
        None => None,
    }
}

/// `npm exec`, `pnpm dlx`, ...: the subcommand is the first word. Global
/// options before it are not parsed (a value can look like a
/// subcommand), so a run subcommand anywhere after one holds the words to
/// the launcher rule.
fn sub_runner(lits: &[Option<String>], subs: &[(&str, &'static Opts)]) -> Option<Launch> {
    let is_sub = |w: &Option<String>| {
        w.as_deref()
            .is_none_or(|a| subs.iter().any(|(s, _)| *s == a))
    };
    if let Some(Some(sub)) = lits.get(1)
        && let Some((_, spec)) = subs.iter().find(|(s, _)| s == sub)
    {
        return Some(walk(spec, lits, 2));
    }
    let optioned = lits
        .get(1)
        .is_some_and(|w| w.as_deref().is_none_or(|a| a.starts_with('-')));
    (optioned && lits[1..].iter().any(is_sub)).then_some(Launch::Strict { from: 1 })
}

/// `bun x` is `bunx`; `bun exec` runs Bun Shell code, which the guard
/// does not read. Other `bun` uses are an interpreter's.
fn bun(lits: &[Option<String>]) -> Option<Launch> {
    let k = lits
        .iter()
        .skip(1)
        .position(|w| w.as_deref() != Some("--bun"))?
        + 1;
    match lits[k].as_deref() {
        Some("x") => Some(walk(&BUNX, lits, k + 1)),
        Some("exec") => Some(Launch::Deny(
            "bun exec runs Bun Shell code, which the guard does not read (G3)".into(),
        )),
        // Other options first (`--env-file F x ...`): their values are
        // not parsed here.
        Some(a) if a.starts_with('-') => lits[k..]
            .iter()
            .any(|w| matches!(w.as_deref(), Some("x" | "exec") | None))
            .then_some(Launch::Strict { from: 1 }),
        _ => None,
    }
}

/// `cargo run` builds and runs a binary; in tollgate's own repo that is
/// tollgate, so its person-only subcommands deny (R25) anywhere in the
/// words after `run`.
fn cargo(lits: &[Option<String>]) -> Option<Launch> {
    let k = lits
        .iter()
        .skip(1)
        .position(|w| w.as_deref().is_none_or(|a| !a.starts_with(['-', '+'])))?
        + 1;
    if !matches!(lits[k].as_deref(), Some("run" | "r")) {
        return None;
    }
    let words: Vec<String> = lits[k + 1..]
        .iter()
        .flatten()
        .filter(|w| !w.starts_with('-'))
        .map(|w| w.to_lowercase())
        .collect();
    let words: Vec<&str> = words.iter().map(String::as_str).collect();
    (0..words.len())
        .find_map(|i| cmds::person_only(&words[i..]))
        .map(|why| Launch::Deny(format!("cargo run may run tollgate here: {why}")))
}

const STRACE: Opts = Opts {
    short_flags: "AcCdDfFhiknqrtTvVwxyzZ",
    short_val: "abeEIoOpPsSuUX",
    long_flags: &[
        "follow-forks",
        "output-separately",
        "summary-only",
        "summary",
        "summary-wall-clock",
        "no-abbrev",
        "verbose",
        "raw",
        "timestamps",
        "absolute-timestamps",
        "relative-timestamps",
        "syscall-times",
        "instruction-pointer",
        "stack-trace",
        "decode-fds",
        "decode-pids",
        "quiet",
        "debug",
        "help",
        "version",
        "seccomp-bpf",
        "kill-on-exit",
        "daemonize",
    ],
    long_val: &[
        "trace",
        "signal",
        "status",
        "output",
        "attach",
        "trace-path",
        "string-limit",
        "summary-columns",
        "summary-sort-by",
        "user",
        "env",
        "columns",
    ],
    ..NONE
};

const LTRACE: Opts = Opts {
    short_flags: "bcCfhiLrStTV",
    short_val: "aAeEnDFlopsuwx",
    long_flags: &["demangle", "help", "version"],
    long_val: &["align", "indent", "library", "output", "config"],
    ..NONE
};

const PERF: Opts = Opts {
    short_flags: "aAdgivnqsBTWN",
    short_val: "eoptCcFGrxIjmMLu",
    long_val: &[
        "event",
        "output",
        "pid",
        "tid",
        "cpu",
        "repeat",
        "call-graph",
    ],
    ..NONE
};

const CHRONIC: Opts = Opts {
    short_flags: "ev",
    ..NONE
};

const XVFB_RUN: Opts = Opts {
    short_flags: "alh",
    short_val: "nfspew",
    long_flags: &["auto-servernum", "listen-tcp", "help"],
    long_val: &[
        "server-num",
        "auth-file",
        "server-args",
        "xauth-protocol",
        "error-file",
        "wait",
    ],
    ..NONE
};

const SYSTEMD_INHIBIT: Opts = Opts {
    short_flags: "h",
    long_flags: &["list", "no-pager", "no-legend", "help", "version"],
    long_val: &["what", "who", "why", "mode"],
    ..NONE
};

const SYSTEMD_CAT: Opts = Opts {
    short_flags: "h",
    short_val: "tp",
    long_flags: &["help", "version"],
    long_val: &[
        "identifier",
        "priority",
        "stderr-priority",
        "level-prefix",
        "namespace",
    ],
    ..NONE
};

const UV_RUN: Opts = Opts {
    short_flags: "qvUnmsh",
    short_val: "wifPCp",
    long_flags: &[
        "isolated",
        "no-env-file",
        "no-index",
        "upgrade",
        "no-sources",
        "reinstall",
        "compile-bytecode",
        "no-build-isolation",
        "no-build",
        "no-binary",
        "no-cache",
        "refresh",
        "managed-python",
        "no-managed-python",
        "no-python-downloads",
        "quiet",
        "verbose",
        "native-tls",
        "offline",
        "no-progress",
        "no-config",
        "help",
        "version",
        "frozen",
        "all-extras",
        "no-dev",
        "no-default-groups",
        "all-groups",
        "module",
        "only-dev",
        "no-editable",
        "exact",
        "active",
        "no-sync",
        "locked",
        "script",
        "gui-script",
        "all-packages",
        "no-project",
    ],
    long_val: &[
        "with",
        "with-editable",
        "with-requirements",
        "env-file",
        "python-platform",
        "index",
        "default-index",
        "index-url",
        "extra-index-url",
        "find-links",
        "index-strategy",
        "keyring-provider",
        "upgrade-package",
        "resolution",
        "prerelease",
        "fork-strategy",
        "exclude-newer",
        "exclude-newer-package",
        "reinstall-package",
        "link-mode",
        "config-setting",
        "config-settings-package",
        "no-build-isolation-package",
        "no-build-package",
        "no-binary-package",
        "cache-dir",
        "refresh-package",
        "python",
        "color",
        "allow-insecure-host",
        "directory",
        "project",
        "config-file",
        "package",
        "extra",
        "no-extra",
        "group",
        "no-group",
        "only-group",
    ],
    ..NONE
};

const UVX: Opts = Opts {
    short_flags: "qvUnhV",
    short_val: "wcbifPCp",
    long_flags: &[
        "isolated",
        "no-env-file",
        "no-index",
        "upgrade",
        "no-sources",
        "reinstall",
        "compile-bytecode",
        "no-build-isolation",
        "no-build",
        "no-binary",
        "no-cache",
        "refresh",
        "managed-python",
        "no-managed-python",
        "no-python-downloads",
        "quiet",
        "verbose",
        "native-tls",
        "offline",
        "no-progress",
        "no-config",
        "help",
        "version",
        "lfs",
    ],
    long_val: &[
        "with",
        "with-editable",
        "with-requirements",
        "env-file",
        "python-platform",
        "index",
        "default-index",
        "index-url",
        "extra-index-url",
        "find-links",
        "index-strategy",
        "keyring-provider",
        "upgrade-package",
        "resolution",
        "prerelease",
        "fork-strategy",
        "exclude-newer",
        "exclude-newer-package",
        "reinstall-package",
        "link-mode",
        "config-setting",
        "config-settings-package",
        "no-build-isolation-package",
        "no-build-package",
        "no-binary-package",
        "cache-dir",
        "refresh-package",
        "python",
        "color",
        "allow-insecure-host",
        "directory",
        "project",
        "config-file",
        "from",
        "constraints",
        "build-constraints",
        "overrides",
        "torch-backend",
    ],
    ..NONE
};

/// `npx` and `npm exec` (npm 10): `-c` takes a shell string.
const NPX: Opts = Opts {
    short_flags: "y",
    short_val: "pwc",
    long_flags: &[
        "yes",
        "no",
        "workspaces",
        "include-workspace-root",
        "strict-allow-scripts",
        "dangerously-allow-all-scripts",
    ],
    long_val: &["package", "call", "workspace", "allow-scripts"],
    ..NONE
};

/// `pnpm dlx` and `pnpx`: `-c` runs the command with a shell.
const PNPM_DLX: Opts = Opts {
    short_flags: "cs",
    long_flags: &["shell-mode", "silent"],
    long_val: &["package", "allow-build"],
    ..NONE
};

const PNPM_EXEC: Opts = Opts {
    short_flags: "rc",
    long_flags: &[
        "recursive",
        "parallel",
        "shell-mode",
        "no-reporter-hide-prefix",
        "report-summary",
    ],
    long_val: &["resume-from", "filter", "workspace-concurrency"],
    ..NONE
};

const YARN_DLX: Opts = Opts {
    short_flags: "q",
    short_val: "p",
    long_flags: &["quiet"],
    long_val: &["package"],
    ..NONE
};

/// `bunx` and `bun x` (bun 1.3).
const BUNX: Opts = Opts {
    short_val: "p",
    long_flags: &[
        "bun",
        "no-install",
        "trust",
        "ignore-scripts",
        "verbose",
        "silent",
    ],
    long_val: &[
        "package",
        "cwd",
        "registry",
        "ca",
        "cafile",
        "minimum-release-age",
        "env-file",
    ],
    ..NONE
};

#[cfg(test)]
mod tests {
    use super::*;

    fn lits(words: &[&str]) -> Vec<Option<String>> {
        words.iter().map(|w| Some((*w).to_owned())).collect()
    }

    fn at(words: &[&str]) -> Option<Launch> {
        launch(words[0], &lits(words))
    }

    #[test]
    fn the_command_is_found_after_each_runners_options() {
        let w = |at, prefix, moved| Some(Launch::Walk { at, prefix, moved });
        assert_eq!(at(&["uv", "run", "pytest", "-q"]), w(2, &[], false));
        assert_eq!(at(&["uv", "-q", "run", "--", "git"]), w(4, &[], false));
        assert_eq!(
            at(&["uv", "run", "--with", "rich", "env"]),
            w(4, &[], false)
        );
        assert_eq!(
            at(&["uv", "run", "-m", "pytest"]),
            w(3, &["python", "-m"], false)
        );
        assert_eq!(at(&["uv", "run", "--directory", "d", "x"]), w(4, &[], true));
        assert_eq!(at(&["uv", "tool", "run", "ruff"]), w(3, &[], false));
        assert_eq!(at(&["uv", "pip", "install", "x"]), None);
        assert_eq!(at(&["uvx", "--from", "x", "ruff"]), w(3, &[], false));
        assert_eq!(at(&["npx", "-y", "prettier"]), w(2, &[], false));
        assert_eq!(at(&["npm", "exec", "--", "git"]), w(3, &[], false));
        assert_eq!(at(&["npm", "install"]), None);
        assert_eq!(at(&["bun", "x", "tsc"]), w(2, &[], false));
        assert_eq!(at(&["bun", "test"]), None);
        assert_eq!(
            at(&["strace", "-f", "-o", "/tmp/t", "ls"]),
            w(4, &[], false)
        );
        assert_eq!(
            at(&["valgrind", "--tool=memcheck", "-q", "ls"]),
            w(3, &[], false)
        );
        assert_eq!(
            at(&["perf", "stat", "-e", "cycles", "ls"]),
            w(4, &[], false)
        );
        assert_eq!(
            at(&["xvfb-run", "-a", "-s", "-screen 0", "x"]),
            w(4, &[], false)
        );
        assert_eq!(at(&["cargo", "build"]), None);
        assert_eq!(at(&["cargo", "run", "--", "status"]), None);
    }

    #[test]
    fn unknown_options_shell_strings_and_env_files_never_walk() {
        assert_eq!(
            at(&["strace", "--frobnicate", "git"]),
            Some(Launch::Strict { from: 1 })
        );
        assert_eq!(
            at(&["npx", "-c", "git commit"]),
            Some(Launch::Strict { from: 1 })
        );
        assert_eq!(
            at(&["pnpm", "dlx", "-c", "git commit"]),
            Some(Launch::Strict { from: 2 })
        );
        for words in [
            &["npm", "--prefix", "x", "exec", "git"][..],
            &["npm", "--prefix", "/x", "exec", "-c", "git commit"],
            &["pnpm", "--dir", "/x", "dlx", "-c", "git commit"],
            &["bun", "--env-file", ".env", "x", "cargo"],
        ] {
            assert_eq!(at(words), Some(Launch::Strict { from: 1 }), "{words:?}");
        }
        assert_eq!(
            at(&["uv", "--directory", "d", "run", "./x"]),
            Some(Launch::Walk {
                at: 4,
                prefix: &[],
                moved: true
            })
        );
        for words in [
            &["uv", "run", "--env-file", ".env", "cargo"][..],
            &["uv", "run", "--env-f", ".env", "cargo"],
            &["uvx", "--env-file=.env", "ruff"],
            &["bunx", "--env-file", ".env", "x"],
            &["strace", "-E", "GIT_CONFIG_COUNT=0", "cargo"],
            &["bun", "exec", "git commit"],
            &["uv", "--env-file", ".env", "run", "cargo"],
            &["uv", "--env-file=.env", "tool", "run", "ruff"],
            &["cargo", "run", "--", "remotes", "forget"],
            &[
                "cargo", "+nightly", "r", "-q", "--bin", "tollgate", "--", "install",
            ],
        ] {
            assert!(matches!(at(words), Some(Launch::Deny(_))), "{words:?}");
        }
    }
}
