//! Command tables of the grammar (G2, G3, G5): what each command name is
//! to the guard, the options of the pass-through wrappers, the sensitive
//! variables, and the scan of inline interpreter code.

/// What a command name is to the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// G2a: runs its operand command with literal argv.
    Wrapper(&'static str),
    /// G2b: runs its command as another user, elsewhere or with another
    /// environment.
    Launcher(&'static str),
    /// G3: a shell (`sh -c`, a script file, or a program on stdin).
    Shell(&'static str),
    /// G3: `eval`.
    Eval,
    /// G3: `source` and `.`.
    Source,
    /// G3: an interpreter whose inline code is scanned.
    Interp(Lang),
    /// G5: a builtin that writes shell variables.
    VarWrite(&'static str),
    /// G8: `cd`, `pushd`, `popd`.
    Cd(&'static str),
    /// `busybox <applet>`.
    Busybox,
    Other,
}

/// Interpreter languages (G3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    Python,
    Perl,
    Ruby,
    Node,
    Bun,
    Deno,
    Php,
    Lua,
    Awk,
}

/// Shells (G3).
pub const SHELLS: &[&str] = &[
    "sh", "bash", "rbash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "yash", "csh", "tcsh",
];

const WRAPPERS: &[&str] = &[
    "env", "command", "builtin", "exec", "nohup", "timeout", "nice", "ionice", "stdbuf", "time",
    "taskset", "setsid", "flock", "chrt", "unbuffer", "xargs", "find", "parallel",
];

const LAUNCHERS: &[&str] = &[
    "sudo",
    "doas",
    "su",
    "runuser",
    "setpriv",
    "pkexec",
    "systemd-run",
    "machinectl",
    "ssh",
    "tmux",
    "screen",
    "at",
    "batch",
    "kitty",
    "kitten",
    "docker",
    "podman",
    "nsenter",
    "unshare",
    "chroot",
    "bwrap",
    "firejail",
    "flatpak-spawn",
    "busctl",
    "dbus-send",
    "script",
    "watch",
];

const VAR_WRITERS: &[&str] = &[
    "export",
    "declare",
    "typeset",
    "local",
    "readonly",
    "unset",
    "read",
    "mapfile",
    "readarray",
    "printf",
    "getopts",
    "let",
];

/// The class of command name `base` (a basename).
#[must_use]
pub fn classify(base: &str) -> Class {
    if let Some(w) = WRAPPERS.iter().find(|n| **n == base) {
        return Class::Wrapper(w);
    }
    if let Some(l) = LAUNCHERS.iter().find(|n| **n == base) {
        return Class::Launcher(l);
    }
    if let Some(s) = SHELLS.iter().find(|n| **n == base) {
        return Class::Shell(s);
    }
    if let Some(v) = VAR_WRITERS.iter().find(|n| **n == base) {
        return Class::VarWrite(v);
    }
    match base {
        "eval" => Class::Eval,
        "source" | "." => Class::Source,
        "cd" => Class::Cd("cd"),
        "pushd" => Class::Cd("pushd"),
        "popd" => Class::Cd("popd"),
        "busybox" => Class::Busybox,
        _ => interp(base).map_or(Class::Other, Class::Interp),
    }
}

/// The interpreter `base` names, if any (`python3.12` included).
#[must_use]
pub fn interp(base: &str) -> Option<Lang> {
    let versioned = |stem: &str| {
        base.strip_prefix(stem)
            .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
    };
    if versioned("python") || versioned("pypy") {
        return Some(Lang::Python);
    }
    if versioned("perl") {
        return Some(Lang::Perl);
    }
    if versioned("ruby") {
        return Some(Lang::Ruby);
    }
    if versioned("php") {
        return Some(Lang::Php);
    }
    if versioned("lua") || base == "luajit" {
        return Some(Lang::Lua);
    }
    match base {
        "node" | "nodejs" => Some(Lang::Node),
        "bun" => Some(Lang::Bun),
        "deno" => Some(Lang::Deno),
        "awk" | "gawk" | "mawk" | "nawk" => Some(Lang::Awk),
        _ => None,
    }
}

/// Names a function must not take: it would change what the guard thinks
/// a command does.
#[must_use]
pub fn reserved_function_name(name: &str) -> bool {
    classify(name) != Class::Other
        || matches!(
            name,
            "git" | "tollgate" | "alias" | "hash" | "trap" | "enable" | "rm" | "mv" | "cp" | "ln"
        )
        || name.starts_with("git-")
}

/// Why writing variable `name` is denied (G5) in any position, except
/// [`scoped`] ones and `TOLLGATE_INLINE_CAP` (G6).
#[must_use]
pub fn sensitive(name: &str) -> Option<&'static str> {
    if matches!(name, "GIT_CONFIG_COUNT" | "GIT_CONFIG_PARAMETERS")
        || name.starts_with("GIT_CONFIG_KEY_")
        || name.starts_with("GIT_CONFIG_VALUE_")
    {
        return Some("carries the hook injection");
    }
    if name.starts_with("GIT_SSH") || name == "GIT_PROXY_COMMAND" {
        return Some("picks the program git reaches a server with (X1)");
    }
    match name {
        "GIT_EXEC_PATH" => Some("changes which git programs git and the gate hooks run (X1)"),
        "BASH_ENV" | "ENV" | "PROMPT_COMMAND" | "SHELLOPTS" | "BASHOPTS" => {
            Some("makes a shell run code the guard does not read (G3)")
        }
        "LESSOPEN" | "LESSCLOSE" => Some("makes less run a program on each file it shows (G3)"),
        "PS0" | "PS1" | "PS2" | "PS4" => Some(
            "is a prompt bash expands with command substitution (PS4 on every `set -x` line) (G3)",
        ),
        n if n.starts_with("TOLLGATE_") && n != "TOLLGATE_INLINE_CAP" => {
            Some("is tollgate's own setting")
        }
        _ => None,
    }
}

/// Which commands a [`scoped`] variable matters to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// git and tollgate.
    GitOrTollgate,
    /// tollgate only: the hooks take their dirs from `install.json`.
    Tollgate,
}

/// Variables denied only in a command that also runs git or tollgate
/// (G5, R8): they choose the repo, the config files or the records those
/// read, and nothing else. `GIT_INDEX_FILE` is not one: the gate hooks
/// check the index git gives them (R17).
#[must_use]
pub fn scoped(name: &str) -> Option<(Reach, &'static str)> {
    match name {
        "HOME"
        | "XDG_CONFIG_HOME"
        | "GIT_CONFIG"
        | "GIT_CONFIG_GLOBAL"
        | "GIT_CONFIG_SYSTEM"
        | "GIT_CONFIG_NOSYSTEM" => Some((
            Reach::GitOrTollgate,
            "decides which config files git and tollgate read",
        )),
        "GIT_DIR" | "GIT_WORK_TREE" | "GIT_COMMON_DIR" => Some((
            Reach::GitOrTollgate,
            "changes which repo and work tree git and the gate hooks use",
        )),
        "XDG_STATE_HOME" | "XDG_DATA_HOME" => Some((
            Reach::Tollgate,
            "changes which records and binary tollgate uses",
        )),
        _ => None,
    }
}

/// Variables allowed in front of a gated git or tollgate command (G4).
pub const GATED_ENV: &[&str] = &[
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "EDITOR",
    "VISUAL",
    "GIT_PAGER",
    "PAGER",
    "LC_ALL",
    "LANG",
    "TZ",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_AUTHOR_DATE",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "GIT_COMMITTER_DATE",
    "GIT_TERMINAL_PROMPT",
    "GIT_INDEX_FILE",
    "TOLLGATE_INLINE_CAP",
];

/// [`GATED_ENV`] variables whose value git runs as shell code.
pub const CODE_ENV: &[&str] = &[
    "GIT_EDITOR",
    "GIT_SEQUENCE_EDITOR",
    "EDITOR",
    "VISUAL",
    "GIT_PAGER",
    "PAGER",
];

/// Splits literal text into the words a shell or a launcher may run:
/// blanks, shell operators, quotes and `=` separate them.
pub fn tokens(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                ';' | '&' | '|' | '(' | ')' | '<' | '>' | '`' | '\'' | '"' | '$' | '=' | '{' | '}'
            )
    })
    .filter(|t| !t.is_empty())
}

/// What a token runs, when it is git, tollgate, a shell or an interpreter
/// (G2): the reason text.
#[must_use]
pub fn forbidden(token: &str, git_known: &[&str]) -> Option<&'static str> {
    let base = token.rsplit('/').next().unwrap_or(token);
    if base == "git"
        || base
            .strip_prefix("git-")
            .is_some_and(|s| git_known.contains(&s))
    {
        return Some("git");
    }
    if base.eq_ignore_ascii_case("tollgate") {
        return Some("tollgate");
    }
    if SHELLS.contains(&base) || base == "busybox" {
        return Some("a shell");
    }
    if interp(base).is_some() {
        return Some("an interpreter");
    }
    None
}

/// Option grammar of a wrapper (getopt and getopt_long rules: short
/// clusters, values glued or in the next word, long options as unique
/// prefixes with `=` or the next word). Options it does not list are
/// refused (the grammar is closed).
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    pub short_flags: &'static str,
    pub short_val: &'static str,
    /// Short options whose value is optional and only glued.
    pub short_opt: &'static str,
    pub long_flags: &'static [&'static str],
    pub long_val: &'static [&'static str],
    /// Long options whose value is optional and only after `=`.
    pub long_opt: &'static [&'static str],
}

/// One parsed option: its name (`-x` or `--long`, long names in full) and
/// its value (`Some` with the word index for a separate value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opt {
    pub name: String,
    pub value: Option<OptValue>,
}

/// Where an option's value is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptValue {
    Glued(String),
    Word(usize),
}

/// True when the literal options from `words[1]` on hold one of `no_run`
/// (an option after which the wrapper runs nothing) before the first word
/// bash builds at run time; only clusters of plain flags count.
#[must_use]
pub fn no_run_first(spec: &Opts, words: &[Option<String>], no_run: &[&str]) -> bool {
    for w in words.iter().skip(1) {
        let Some(a) = w.as_deref() else {
            return false;
        };
        if a == "--" || a == "-" || !a.starts_with('-') {
            return false;
        }
        if a.starts_with("--") {
            if no_run.contains(&a.split('=').next().unwrap_or(a)) {
                return true;
            }
            continue;
        }
        if !a[1..].chars().all(|c| spec.short_flags.contains(c)) {
            return false;
        }
        if a[1..]
            .chars()
            .any(|c| no_run.contains(&format!("-{c}").as_str()))
        {
            return true;
        }
    }
    false
}

/// Parses options from `words[start..]` (`None` for a non-literal word).
/// Returns the options and the index of the first operand.
///
/// # Errors
/// A non-literal word where an option may be, an unknown or ambiguous
/// option, or a missing value.
pub fn parse_opts(
    spec: &Opts,
    words: &[Option<String>],
    start: usize,
) -> Result<(Vec<Opt>, usize), String> {
    let mut out = Vec::new();
    let mut i = start;
    while i < words.len() {
        let Some(a) = words[i].as_deref() else {
            return Err("a word bash builds at run time where options are read".into());
        };
        if a == "--" {
            return Ok((out, i + 1));
        }
        if a == "-" || !a.starts_with('-') {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (long, None),
            };
            let all = spec
                .long_flags
                .iter()
                .chain(spec.long_val)
                .chain(spec.long_opt);
            let exact = all.clone().find(|n| **n == name);
            let full = match exact {
                Some(n) => *n,
                None => {
                    let hits: Vec<&&str> = all.filter(|n| n.starts_with(name)).collect();
                    match hits.as_slice() {
                        [one] if !name.is_empty() => **one,
                        [] => return Err(format!("unknown option --{name}")),
                        _ => return Err(format!("ambiguous option --{name}")),
                    }
                }
            };
            let value = if spec.long_val.contains(&full) {
                match glued {
                    Some(v) => Some(OptValue::Glued(v)),
                    None => {
                        i += 1;
                        if i >= words.len() {
                            return Err(format!("--{full} without its value"));
                        }
                        Some(OptValue::Word(i))
                    }
                }
            } else if spec.long_opt.contains(&full) {
                glued.map(OptValue::Glued)
            } else if glued.is_some() {
                return Err(format!("--{full} takes no value"));
            } else {
                None
            };
            out.push(Opt {
                name: format!("--{full}"),
                value,
            });
            i += 1;
            continue;
        }
        let cluster = &a[1..];
        for (k, c) in cluster.char_indices() {
            let rest = &cluster[k + c.len_utf8()..];
            if spec.short_val.contains(c) {
                let value = if rest.is_empty() {
                    i += 1;
                    if i >= words.len() {
                        return Err(format!("-{c} without its value"));
                    }
                    OptValue::Word(i)
                } else {
                    OptValue::Glued(rest.to_owned())
                };
                out.push(Opt {
                    name: format!("-{c}"),
                    value: Some(value),
                });
                break;
            }
            if spec.short_opt.contains(c) {
                out.push(Opt {
                    name: format!("-{c}"),
                    value: (!rest.is_empty()).then(|| OptValue::Glued(rest.to_owned())),
                });
                break;
            }
            if spec.short_flags.contains(c) {
                out.push(Opt {
                    name: format!("-{c}"),
                    value: None,
                });
                continue;
            }
            return Err(format!("unknown option -{c}"));
        }
        i += 1;
    }
    Ok((out, i))
}

/// A wrapper's option grammar, its positional words before the command,
/// and the options after which no command runs.
#[must_use]
pub fn wrapper_opts(name: &str) -> (Opts, usize, &'static [&'static str]) {
    const NONE: Opts = Opts {
        short_flags: "",
        short_val: "",
        short_opt: "",
        long_flags: &["help", "version"],
        long_val: &[],
        long_opt: &[],
    };
    const HELP: &[&str] = &["--help", "--version"];
    match name {
        "command" => (
            Opts {
                short_flags: "pvV",
                ..NONE
            },
            0,
            &["-v", "-V"],
        ),
        "exec" => (
            Opts {
                short_flags: "cl",
                short_val: "a",
                ..NONE
            },
            0,
            &[],
        ),
        "timeout" => (
            Opts {
                short_flags: "fpv",
                short_val: "ks",
                long_flags: &[
                    "foreground",
                    "preserve-status",
                    "verbose",
                    "help",
                    "version",
                ],
                long_val: &["kill-after", "signal"],
                ..NONE
            },
            1,
            HELP,
        ),
        "nice" => (
            Opts {
                short_flags: "0123456789",
                short_val: "n",
                long_val: &["adjustment"],
                ..NONE
            },
            0,
            HELP,
        ),
        "ionice" => (
            Opts {
                short_flags: "t",
                short_val: "cnpPu",
                long_flags: &["ignore", "help", "version"],
                long_val: &["class", "classdata", "pid", "pgid", "uid"],
                ..NONE
            },
            0,
            &[
                "-p",
                "-P",
                "-u",
                "--pid",
                "--pgid",
                "--uid",
                "--help",
                "--version",
            ],
        ),
        "stdbuf" => (
            Opts {
                short_val: "ioe",
                long_val: &["input", "output", "error"],
                ..NONE
            },
            0,
            HELP,
        ),
        "time" => (
            Opts {
                short_flags: "apqv",
                short_val: "fo",
                long_flags: &[
                    "append",
                    "portability",
                    "quiet",
                    "verbose",
                    "help",
                    "version",
                ],
                long_val: &["format", "output"],
                ..NONE
            },
            0,
            HELP,
        ),
        "taskset" => (
            Opts {
                short_flags: "acp",
                long_flags: &["all-tasks", "cpu-list", "pid", "help", "version"],
                ..NONE
            },
            1,
            &["-p", "--pid", "--help", "--version"],
        ),
        "setsid" => (
            Opts {
                short_flags: "cfw",
                long_flags: &["ctty", "fork", "wait", "help", "version"],
                ..NONE
            },
            0,
            HELP,
        ),
        "flock" => (
            Opts {
                short_flags: "sxeunoF",
                short_val: "wE",
                long_flags: &[
                    "shared",
                    "exclusive",
                    "unlock",
                    "nonblock",
                    "nb",
                    "close",
                    "no-fork",
                    "verbose",
                    "help",
                    "version",
                ],
                long_val: &["timeout", "wait", "conflict-exit-code"],
                ..NONE
            },
            1,
            HELP,
        ),
        "chrt" => (
            Opts {
                short_flags: "abdefioRrvmp",
                short_val: "TPD",
                long_flags: &[
                    "all-tasks",
                    "batch",
                    "deadline",
                    "ext",
                    "fifo",
                    "idle",
                    "other",
                    "rr",
                    "reset-on-fork",
                    "verbose",
                    "max",
                    "pid",
                    "help",
                    "version",
                ],
                long_val: &["sched-runtime", "sched-period", "sched-deadline"],
                ..NONE
            },
            1,
            &["-m", "-p", "--max", "--pid", "--help", "--version"],
        ),
        "unbuffer" => (
            Opts {
                short_flags: "p",
                ..NONE
            },
            0,
            &[],
        ),
        "xargs" => (
            Opts {
                short_flags: "0optrx",
                short_val: "adEILnPs",
                short_opt: "eil",
                long_flags: &[
                    "null",
                    "open-tty",
                    "interactive",
                    "no-run-if-empty",
                    "verbose",
                    "exit",
                    "show-limits",
                    "help",
                    "version",
                ],
                long_val: &[
                    "arg-file",
                    "delimiter",
                    "max-args",
                    "max-procs",
                    "max-chars",
                    "process-slot-var",
                ],
                long_opt: &["eof", "replace", "max-lines"],
            },
            0,
            &["--show-limits", "--help", "--version"],
        ),
        // `nohup`, `builtin`, `setsid` without options.
        _ => (NONE, 0, HELP),
    }
}

/// The identifiers in `code`.
pub fn identifiers(code: &str) -> impl Iterator<Item = &str> {
    code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| t.chars().next().is_some_and(|c| !c.is_ascii_digit()))
}

/// Python names that run code or programs from data: dynamic imports,
/// code from strings, deserializers that call functions, and modules
/// that start programs (G3). Matched on the code outside string literals.
const PY_SPAWN: &[&str] = &[
    "__import__",
    "importlib",
    "eval",
    "runpy",
    "timeit",
    "ctypes",
    "cffi",
    "pickle",
    "cPickle",
    "dill",
    "cloudpickle",
    "marshal",
    "shelve",
    "webbrowser",
    "pydoc",
    "pipepager",
    "FunctionType",
    "CodeType",
    "InteractiveInterpreter",
    "InteractiveConsole",
    "create_subprocess_exec",
    "create_subprocess_shell",
    "pty",
    "multiprocessing",
    // The object graph reaches `os.system` without an import or a name:
    // `().__class__.__base__.__subclasses__()`, a function's globals, a
    // frame's.
    "__subclasses__",
    "__globals__",
    "__code__",
    "__closure__",
    "__reduce__",
    "__reduce_ex__",
    "__loader__",
    "_getframe",
    "f_globals",
    "f_locals",
    "f_builtins",
    "gi_frame",
    "tb_frame",
    "breakpoint",
];

/// Names in code of the other interpreters that run code built from a
/// string or reach a function by a string (G3): `eval`, JavaScript's
/// `Function` and constructor chain, Node's module loader and bindings,
/// Ruby's `send`, Lua's `load`, PHP's callbacks.
const DYNAMIC_CODE: &[&str] = &[
    "eval",
    "evaluate",
    "Function",
    "AsyncFunction",
    "constructor",
    "binding",
    "_linkedBinding",
    "dlopen",
    "_load",
    "runInThisContext",
    "runInNewContext",
    "runInContext",
    "compileFunction",
    "Worker",
    "send",
    "public_send",
    "__send__",
    "instance_eval",
    "class_eval",
    "module_eval",
    "instance_exec",
    "const_get",
    "load",
    "loadstring",
    "dofile",
    "loadfile",
    "assert",
    "create_function",
    "call_user_func",
    "call_user_func_array",
    "preg_replace_callback",
];

/// Python names that reach an attribute by a string (G3) ...
const PY_DYNAMIC: &[&str] = &[
    "getattr",
    "vars",
    "globals",
    "locals",
    "__dict__",
    "__getattribute__",
    "modules",
];

/// ... of these modules.
const PY_MODULES: &[&str] = &[
    "os",
    "posix",
    "sys",
    "builtins",
    "__builtins__",
    "subprocess",
];

/// Python `code` with string literals and comments removed (each literal
/// becomes a blank), so names in text an edit script writes are not taken
/// for calls. A program with an f- or t-string is returned whole: their
/// replacement fields are code that may hold quotes of their own (3.12),
/// which only a full parser follows. A backslash always escapes the next
/// character (raw strings too: `r'\''` does not end at the second quote);
/// a line break ends a one-line literal (Python refuses the program
/// otherwise, so nothing in it runs).
#[must_use]
pub fn python_code(code: &str) -> String {
    let c: Vec<char> = code.chars().collect();
    let mut out = String::with_capacity(code.len());
    let mut i = 0;
    while i < c.len() {
        match c[i] {
            '#' => {
                while i < c.len() && c[i] != '\n' {
                    i += 1;
                }
            }
            q @ ('\'' | '"') => {
                // The letters right before an opening quote are its
                // prefix when they start a token (`f'`, `rb"`), not the
                // end of a name (`elif'`).
                let prefix: Vec<char> = c[..i]
                    .iter()
                    .rev()
                    .take_while(|p| p.is_alphanumeric() || **p == '_')
                    .copied()
                    .collect();
                if prefix.len() <= 2
                    && prefix.iter().any(|p| matches!(p, 'f' | 'F' | 't' | 'T'))
                    && prefix
                        .iter()
                        .all(|p| matches!(p.to_ascii_lowercase(), 'f' | 't' | 'r' | 'b' | 'u'))
                {
                    return code.to_owned();
                }
                let triple = c.get(i + 1) == Some(&q) && c.get(i + 2) == Some(&q);
                i += if triple { 3 } else { 1 };
                while i < c.len() {
                    if c[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if triple {
                        if c[i] == q && c.get(i + 1) == Some(&q) && c.get(i + 2) == Some(&q) {
                            i += 3;
                            break;
                        }
                    } else if c[i] == q || c[i] == '\n' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push(' ');
            }
            ch => {
                out.push(ch);
                i += 1;
            }
        }
    }
    out
}

/// Identifiers of process-spawning primitives in inline code (G3).
const SPAWN: &[&str] = &[
    "system",
    "popen",
    "Popen",
    "subprocess",
    "child_process",
    "spawn",
    "spawnSync",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "posix_spawn",
    "posix_spawnp",
    "exec",
    "execSync",
    "execFile",
    "execFileSync",
    "execl",
    "execle",
    "execlp",
    "execlpe",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "qx",
    "proc_open",
    "shell_exec",
    "passthru",
    "pcntl_exec",
    "Open3",
];

/// Why inline code of `lang` may start a process (G3), or `None`.
#[must_use]
pub fn spawns(lang: Lang, code: &str) -> Option<String> {
    if lang == Lang::Python {
        let code = python_code(code);
        let mut ids = identifiers(&code);
        if let Some(id) = ids.find(|t| SPAWN.contains(t) || PY_SPAWN.contains(t)) {
            return Some(format!("`{id}`"));
        }
        let dynamic = identifiers(&code).any(|t| PY_DYNAMIC.contains(&t));
        let module = identifiers(&code).find(|t| PY_MODULES.contains(t));
        return match (dynamic, module) {
            (true, Some(m)) => Some(format!("dynamic attribute access with `{m}`")),
            _ => None,
        };
    }
    if let Some(id) = identifiers(code).find(|t| SPAWN.contains(t)) {
        return Some(format!("`{id}`"));
    }
    if lang != Lang::Awk
        && let Some(id) = identifiers(code).find(|t| DYNAMIC_CODE.contains(t))
    {
        return Some(format!(
            "`{id}`, which runs code or calls a function named by a string,"
        ));
    }
    match lang {
        // `require(name)`, `import(name)` with a name built at run time.
        Lang::Node | Lang::Bun | Lang::Deno if dynamic_module(code) => {
            return Some("a module loaded by a name built at run time".into());
        }
        // `&{"name"}(...)`, `&$f(...)`: a sub called by a string.
        Lang::Perl if code.contains("&{") || code.contains("&$") => {
            return Some("a sub called by a name built at run time".into());
        }
        // `$f(...)`: a function called by a string.
        Lang::Php if php_variable_call(code) => {
            return Some("a function called by a variable".into());
        }
        _ => {}
    }
    match lang {
        Lang::Perl | Lang::Ruby if code.contains('`') => Some("backquotes".into()),
        Lang::Ruby if code.contains("%x") => Some("%x".into()),
        Lang::Perl if code.contains('|') && identifiers(code).any(|t| t == "open") => {
            Some("a pipe open".into())
        }
        Lang::Lua if identifiers(code).any(|t| t == "execute") => Some("os.execute".into()),
        Lang::Deno if code.contains("Deno.run") || code.contains("Deno.Command") => {
            Some("Deno.Command".into())
        }
        Lang::Awk => awk_pipe(code).then(|| "a pipe (print | cmd, cmd | getline)".into()),
        _ => None,
    }
}

/// True when JavaScript code loads a module whose name is not one string
/// literal: `require(x)`, `require('a' + b)`, `import(x)`.
fn dynamic_module(code: &str) -> bool {
    for key in ["require", "import"] {
        let mut rest = code;
        while let Some(k) = rest.find(key) {
            let before_ok = rest[..k]
                .chars()
                .next_back()
                .is_none_or(|c| !(c.is_alphanumeric() || c == '_' || c == '$' || c == '.'));
            let after = rest[k + key.len()..].trim_start();
            rest = &rest[k + key.len()..];
            if !before_ok {
                continue;
            }
            let Some(arg) = after.strip_prefix('(') else {
                continue;
            };
            let arg = arg.trim_start();
            let Some(q) = arg.chars().next().filter(|c| matches!(c, '\'' | '"')) else {
                return true;
            };
            let body = &arg[1..];
            let Some(end) = body.find(q) else {
                return true;
            };
            if !body[end + 1..].trim_start().starts_with(')') {
                return true;
            }
        }
    }
    false
}

/// True when PHP code calls a variable as a function (`$f(...)`).
fn php_variable_call(code: &str) -> bool {
    let c: Vec<char> = code.chars().collect();
    let mut k = 0;
    while k < c.len() {
        if c[k] == '$' {
            let mut j = k + 1;
            while j < c.len() && (c[j].is_alphanumeric() || c[j] == '_') {
                j += 1;
            }
            while j < c.len() && c[j].is_whitespace() {
                j += 1;
            }
            if j > k + 1 && c.get(j) == Some(&'(') {
                return true;
            }
            k = j.max(k + 1);
            continue;
        }
        k += 1;
    }
    false
}

/// True when an awk program has a `|` outside strings and regex literals
/// (`print | "cmd"`, `"cmd" | getline`); `||` is a logical or.
fn awk_pipe(code: &str) -> bool {
    let c: Vec<char> = code.chars().collect();
    let mut i = 0;
    // The last significant character, to tell a regex `/` from division.
    let mut prev = '\n';
    while i < c.len() {
        match c[i] {
            '"' => {
                i += 1;
                while i < c.len() && c[i] != '"' {
                    if c[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                prev = '"';
            }
            '/' if "\n(,~!{};&|=".contains(prev) || prev.is_whitespace() => {
                i += 1;
                while i < c.len() && c[i] != '/' {
                    if c[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
                prev = '/';
            }
            '|' => {
                if c.get(i + 1) == Some(&'|') {
                    i += 1;
                    prev = '|';
                } else {
                    return true;
                }
            }
            ch if ch.is_whitespace() => {}
            ch => prev = ch,
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lits(v: &[&str]) -> Vec<Option<String>> {
        v.iter().map(|s| Some((*s).to_owned())).collect()
    }

    #[test]
    fn getopt_rules() {
        let (spec, pre, _) = wrapper_opts("timeout");
        let w = lits(&["timeout", "-s", "KILL", "--kill-a=5", "10", "git"]);
        let (opts, first) = parse_opts(&spec, &w, 1).unwrap();
        assert_eq!(first + pre, 5);
        assert_eq!(opts[0].value, Some(OptValue::Word(2)));
        assert_eq!(opts[1].name, "--kill-after");
        assert!(parse_opts(&spec, &lits(&["timeout", "--bogus", "1", "x"]), 1).is_err());
        assert!(parse_opts(&spec, &[Some("timeout".into()), None], 1).is_err());
        let (spec, _, _) = wrapper_opts("xargs");
        let (opts, first) =
            parse_opts(&spec, &lits(&["xargs", "-0rI{}", "git", "add"]), 1).unwrap();
        assert_eq!(first, 2);
        assert_eq!(
            opts.last().unwrap().value,
            Some(OptValue::Glued("{}".into()))
        );
    }

    #[test]
    fn spawn_primitives_g3() {
        for (lang, code) in [
            (Lang::Python, "import os; os.system('git commit -n')"),
            (Lang::Python, "import subprocess; subprocess.run(['git'])"),
            (Lang::Perl, "print `git commit -n`"),
            (Lang::Perl, "open(F, '|git commit -n')"),
            (Lang::Ruby, "%x(git commit -n)"),
            (
                Lang::Node,
                "require('child_process').execSync('git commit -n')",
            ),
            (Lang::Bun, "Bun.spawn(['git','commit','-n'])"),
            (Lang::Lua, "os.execute('git commit -n')"),
            (Lang::Php, "shell_exec('git commit -n');"),
            (Lang::Awk, "BEGIN { system(\"git commit -n\") }"),
            (Lang::Awk, "{ print | \"sh\" }"),
            (Lang::Awk, "BEGIN { \"git commit -n\" | getline x }"),
        ] {
            assert!(spawns(lang, code).is_some(), "{code}");
        }
        for (lang, code) in [
            (
                Lang::Python,
                "import json,sys; print(json.load(sys.stdin)[\"x\"])",
            ),
            (Lang::Awk, "/a|b/ { print $1 }"),
            (Lang::Awk, "$1 == \"x|y\" || NR > 2 { print }"),
            (Lang::Perl, "print if /fix/"),
        ] {
            assert_eq!(spawns(lang, code), None, "{code}");
        }
    }

    /// Names in Python string literals and comments are text an edit
    /// script writes, not calls (item 42); f- and t-strings hold code, so a
    /// program with one is scanned whole.
    #[test]
    fn python_text_in_strings_is_not_a_call_g3() {
        for code in [
            r#"p='a.rs'; s=open(p).read()
s=s.replace('Command::new("git").spawn()', 'x')
open(p,'w').write(s)"#,
            r#"s = '''
fn run() { exec(cmd); system("x") }
'''
# subprocess is mentioned here
print(len(s))"#,
            r#"s = r'\\' + "os.system"
print(s)"#,
            r#"b = b'popen'; u = u"spawn"; print(b, u)"#,
            r#"x = """a "quoted" exec""" ; print(x)"#,
        ] {
            assert_eq!(spawns(Lang::Python, code), None, "{code}");
        }
        for code in [
            "import os\nos.system('git commit -n')",
            "x = 'a' ; __import__('o' 's').system('x')",
            "import importlib; importlib.import_module('os')",
            "exec('print(1)')",
            "eval(compile('1', 'f', 'eval'))",
            "import timeit; timeit.timeit('x', setup='import os')",
            r"s = '\'' ; os.system('git')",
            r"s = 'abc\n' ; subprocess.run(['git'])",
            "f'{x}' ; v = 'system'",
            r#"f"{'"'}" ; v = 'x' ; os.system('git commit -n')"#,
            "rf'{x}' 'exec'",
            "t'{x}' 'spawn'",
            "getattr(os, 'sys' + 'tem')('git commit -n')",
            "import ctypes; ctypes.CDLL(None).system(b'x')",
            "import pickle; pickle.loads(b'...')",
            "import asyncio; asyncio.create_subprocess_exec('git')",
            "import webbrowser; webbrowser.open('x')",
        ] {
            assert!(spawns(Lang::Python, code).is_some(), "{code}");
        }
    }

    #[test]
    fn tokens_and_forbidden_words_g2() {
        let known = ["commit", "push"];
        let t: Vec<&str> = tokens("journalctl -u app --since \"1 hour ago\"").collect();
        assert_eq!(t[0], "journalctl");
        assert!(tokens("cd /x && git commit -n").any(|t| forbidden(t, &known).is_some()));
        assert!(tokens("--shell=/bin/bash").any(|t| forbidden(t, &known).is_some()));
        assert!(forbidden("git-server", &known).is_none());
        assert!(forbidden("git-commit", &known).is_some());
        assert!(forbidden("python3.12", &known).is_some());
        assert!(forbidden("psql", &known).is_none());
    }
}
