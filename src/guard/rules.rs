//! The guard's text rules (R25 deny, R26 ask, R28 rewrite trigger).
//!
//! Two layers:
//!
//! - Substring rules on the normalized text (lowercase, quotes and
//!   backslashes removed, whitespace collapsed): they see everything,
//!   heredoc bodies and commit messages included, and err toward deny.
//! - Word rules on the parsed simple commands ([`super::shell`]), after
//!   wrappers (`env`, `sudo`, `xargs`, `bash -c`, ...) are stripped: git
//!   flags (`-n`, `-c <key>`), git subcommands, branch renames, and writes
//!   to tollgate's dirs.

use std::path::{Component, Path, PathBuf};

use globset::GlobSet;

use super::shell::{self, SimpleCommand};

/// The guard's verdict on one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ruling {
    /// No rule matched.
    Allow,
    /// `permissionDecision: "ask"` with this reason (R26).
    Ask(String),
    /// Exit 2 with this reason (R25).
    Deny(String),
}

impl Ruling {
    fn rank(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Ask(_) => 1,
            Self::Deny(_) => 2,
        }
    }

    /// The stronger of two rulings (deny > ask > allow; the first wins a
    /// tie).
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Paths and patterns the rules need.
#[derive(Debug, Clone)]
pub struct Context {
    /// The tool call's cwd, for relative paths.
    pub cwd: PathBuf,
    /// `$HOME`.
    pub home: PathBuf,
    /// Variables the rules expand in paths (`HOME`, `XDG_*_HOME`).
    pub vars: Vec<(String, String)>,
    /// tollgate's state, data and config dirs (R25: no writes).
    pub protected: Vec<PathBuf>,
    /// The host config (R26: ask, not deny, for Write/Edit).
    pub host_config: PathBuf,
    /// `tiers.full_refs`, matched case-insensitively (R27).
    pub full_refs: GlobSet,
    /// Names the tollgate binary goes by (PATH name, installed copy).
    pub tollgate_names: Vec<String>,
}

/// Lowercase, quotes and backslashes removed, whitespace collapsed (R25).
#[must_use]
pub fn normalize(text: &str) -> String {
    let lowered: String = text
        .chars()
        .filter(|c| !matches!(c, '\'' | '"' | '\\' | '`'))
        .flat_map(char::to_lowercase)
        .collect();
    lowered.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// R25 substrings that deny wherever they appear.
const DENY_SUBSTRINGS: &[(&str, &str)] = &[
    ("--no-verify", "--no-verify skips the gate hooks"),
    (
        "git_config_count",
        "GIT_CONFIG_* carries the hook injection",
    ),
    ("git_config_key", "GIT_CONFIG_* carries the hook injection"),
    (
        "git_config_value",
        "GIT_CONFIG_* carries the hook injection",
    ),
    (
        "git_config_parameters",
        "GIT_CONFIG_PARAMETERS overrides git config",
    ),
    ("env -i", "env -i drops the hook injection"),
    ("env -u git", "env -u GIT_* drops the hook injection"),
    (
        "unset git_config",
        "unset GIT_CONFIG_* drops the hook injection",
    ),
    (
        "export git_config",
        "export GIT_CONFIG_* changes the hook injection",
    ),
    ("tollgate waive", "tollgate waive is not for agents"),
    (
        "tollgate policy approve",
        "policy approval is not for agents",
    ),
    (
        "tollgate baseline record",
        "baseline record needs Victor's terminal (R94)",
    ),
    // L10: the test switch of `install --yes` is not for sessions.
    (
        "tollgate_test_install",
        "TOLLGATE_TEST_INSTALL is for tests only (L10)",
    ),
];

/// R25: an abbreviation of `--no-verify` anywhere in the normalized text.
/// git's option parser takes any unambiguous prefix of a long option, so
/// `--no-veri` is `--no-verify` for `commit` and `push`, and `--no-v` for
/// `am` (verified with git 2.56). Every prefix from `--no-v` on is denied:
/// the ones git finds ambiguous fail in git anyway. `--no-verbose` and
/// other options that only share the start are not prefixes and stay
/// allowed; the full `--no-verify` is a [`DENY_SUBSTRINGS`] rule.
fn no_verify_abbrev(norm: &str) -> bool {
    const FULL: &str = "--no-verify";
    const SHORTEST: &str = "--no-v";
    norm.match_indices(SHORTEST).any(|(at, _)| {
        let rest = &norm[at..];
        let end = rest
            .char_indices()
            .skip(2)
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '-'))
            .map_or(rest.len(), |(i, _)| i);
        FULL.starts_with(&rest[..end])
    })
}

/// Wrapper commands whose arguments are another command, with the options
/// that take a separate value.
const WRAPPERS: &[(&str, &[&str])] = &[
    (
        "env",
        &["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
    ),
    ("command", &[]),
    ("builtin", &[]),
    ("exec", &["-a"]),
    ("nohup", &[]),
    ("time", &[]),
    ("nice", &["-n", "--adjustment"]),
    ("ionice", &["-c", "-n", "-p", "-t"]),
    ("timeout", &["-s", "--signal", "-k", "--kill-after"]),
    (
        "sudo",
        &["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T"],
    ),
    ("doas", &["-u", "-C"]),
    (
        "xargs",
        &[
            "-I",
            "-i",
            "-n",
            "-L",
            "-l",
            "-P",
            "-d",
            "-E",
            "-e",
            "-s",
            "-a",
            "--max-args",
            "--max-procs",
            "--delimiter",
            "--arg-file",
        ],
    ),
    ("stdbuf", &["-i", "-o", "-e"]),
    ("setsid", &[]),
    ("flock", &["-w", "--timeout", "-E", "--conflict-exit-code"]),
    ("chrt", &[]),
    ("taskset", &[]),
    ("unbuffer", &[]),
    ("then", &[]),
    ("do", &[]),
    ("else", &[]),
    ("elif", &[]),
    ("if", &[]),
    ("while", &[]),
    ("until", &[]),
    ("!", &[]),
];

fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// A command after its wrappers (R25).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unwrapped {
    /// The command and its arguments.
    pub words: Vec<String>,
    /// `NAME=VALUE` words that `env` sets for it.
    pub assigns: Vec<String>,
    /// Why a wrapper changes its environment in a way that can drop or
    /// replace the hook injection (`env -i`, `exec -c`, ...).
    pub env_loss: Option<String>,
}

/// The R25 reason for an `env` that starts with an empty environment.
const ENV_CLEARS: &str = "env -i (also --ignore-environment, a bare -, or -i inside -S) starts the command with an empty environment and drops the hook injection";

/// How many `env -S` strings one command may splice. Each string is
/// shorter than the word it came from; the cap only bounds the work.
const MAX_SPLITS: usize = 8;

fn lose(out: &mut Unwrapped, why: &str) {
    out.env_loss.get_or_insert_with(|| why.to_owned());
}

/// The words of an `env -S` string, split like shell words.
fn split_string(value: &str) -> Vec<String> {
    shell::parse(value)
        .into_iter()
        .flat_map(|c| c.assignments.into_iter().chain(c.words))
        .collect()
}

/// One `env` option word: the words it takes, or an `-S` string to splice.
enum EnvOpt {
    Words(usize),
    Split { value: String, words: usize },
}

/// Parses `env` option word `a` (GNU coreutils 9: long options may be
/// abbreviated; `-u`, `-C`, `-a`, `-S` take a value, glued or as the next
/// word).
fn env_option(a: &str, next: Option<&str>, out: &mut Unwrapped) -> EnvOpt {
    if let Some(long) = a.strip_prefix("--") {
        let (name, value) = match long.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (long, None),
        };
        let abbrev = |full: &str| !name.is_empty() && full.starts_with(name);
        if abbrev("ignore-environment") {
            // `--i` and `--ignore-` are ambiguous; env fails on them.
            lose(out, ENV_CLEARS);
        } else if abbrev("env0-from") {
            lose(
                out,
                "env --env0-from sets variables from a file, which can replace the hook injection",
            );
        } else if abbrev("split-string") {
            return match (value, next) {
                (Some(v), _) => EnvOpt::Split {
                    value: v.to_owned(),
                    words: 1,
                },
                (None, Some(v)) => EnvOpt::Split {
                    value: v.to_owned(),
                    words: 2,
                },
                (None, None) => EnvOpt::Words(1),
            };
        } else if (abbrev("unset") || abbrev("chdir") || abbrev("argv0")) && value.is_none() {
            return EnvOpt::Words(2);
        }
        return EnvOpt::Words(1);
    }
    let cluster = &a[1..];
    for (k, c) in cluster.char_indices() {
        match c {
            'i' => lose(out, ENV_CLEARS),
            'u' | 'C' | 'a' | 'S' => {
                let rest = &cluster[k + c.len_utf8()..];
                let (value, words) = if rest.is_empty() {
                    (next, 2)
                } else {
                    (Some(rest), 1)
                };
                return match (c, value) {
                    ('S', Some(v)) => EnvOpt::Split {
                        value: v.to_owned(),
                        words,
                    },
                    _ => EnvOpt::Words(words),
                };
            }
            _ => {}
        }
    }
    EnvOpt::Words(1)
}

/// `env`'s options, `-` and assignments; returns the index of the command
/// in `w`. An `-S` string is spliced into `w` and parsed again, as env
/// does, so `env -S '-i git commit'` clears the environment and
/// `env -S 'git commit -n'` runs `git commit -n`.
fn env_args(w: &mut Vec<String>, out: &mut Unwrapped) -> usize {
    let mut i = 1;
    let mut splits = 0;
    // Options end at the first operand (getopt with a leading `+`).
    while i < w.len() {
        let a = w[i].as_str();
        if a == "--" {
            i += 1;
            break;
        }
        if a == "-" || !a.starts_with('-') {
            break;
        }
        match env_option(a, w.get(i + 1).map(String::as_str), out) {
            EnvOpt::Words(n) => i += n,
            EnvOpt::Split { value, words } => {
                splits += 1;
                if splits > MAX_SPLITS {
                    lose(out, "env -S nested too deep to check");
                    return w.len();
                }
                let end = (i + words).min(w.len());
                w.splice(i..end, split_string(&value));
            }
        }
    }
    // POSIX: a bare `-` before the assignments means `-i`.
    if w.get(i).is_some_and(|a| a == "-") {
        lose(out, ENV_CLEARS);
        i += 1;
    }
    while let Some(a) = w.get(i)
        && shell::is_assignment(a)
    {
        out.assigns.push(a.clone());
        i += 1;
    }
    i
}

/// bash's `exec [-cl] [-a name]`: returns the index of the command.
fn exec_args(w: &[String], out: &mut Unwrapped) -> usize {
    let mut i = 1;
    while let Some(a) = w.get(i) {
        if a == "--" {
            return i + 1;
        }
        if !a.starts_with('-') || a.len() == 1 {
            break;
        }
        let cluster = &a[1..];
        let mut words = 1;
        for (k, c) in cluster.char_indices() {
            match c {
                'c' => lose(
                    out,
                    "exec -c starts the command with an empty environment and drops the hook injection",
                ),
                'a' => {
                    if cluster[k + 1..].is_empty() {
                        words = 2;
                    }
                    break;
                }
                _ => {}
            }
        }
        i += words;
    }
    i
}

/// The other wrappers: their options (with the values [`WRAPPERS`] lists)
/// and, for `timeout`, `flock`, `chrt` and `taskset`, one positional
/// argument before the command.
fn wrapper_args(name: &str, takes_value: &[&str], w: &[String]) -> usize {
    let mut i = 1;
    while let Some(a) = w.get(i).map(String::as_str) {
        if a == "--" {
            i += 1;
            break;
        }
        if a.starts_with('-') && a.len() > 1 {
            let opt = a.split_once('=').map_or(a, |(o, _)| o);
            i += if takes_value.contains(&opt) && !a.contains('=') {
                2
            } else {
                1
            };
            continue;
        }
        break;
    }
    i + match name {
        "timeout" | "flock" | "chrt" | "taskset" => 1,
        _ => 0,
    }
}

/// The command a wrapper runs: wrappers, their options and (for `env`)
/// assignments stripped, with what `env` sets and whether a wrapper drops
/// the environment. `timeout` also drops its duration, `flock` its lock
/// file.
#[must_use]
pub fn strip_wrappers(words: &[String]) -> Unwrapped {
    let mut out = Unwrapped::default();
    let mut w = words.to_vec();
    while let Some(first) = w.first() {
        let name = basename(first).to_owned();
        let Some((_, takes_value)) = WRAPPERS.iter().find(|(n, _)| *n == name) else {
            break;
        };
        let i = match name.as_str() {
            "env" => env_args(&mut w, &mut out),
            "exec" => exec_args(&w, &mut out),
            _ => wrapper_args(&name, takes_value, &w),
        };
        w.drain(..i.min(w.len()));
    }
    out.words = w;
    out
}

/// One command a Bash command runs.
#[derive(Debug, Clone, Default)]
struct Run {
    /// The command and its arguments, after wrappers.
    words: Vec<String>,
    /// Assignments in front of it: its own, its wrappers' and those of the
    /// shell (`VAR=x sh -c '...'`) that runs it.
    assigns: Vec<String>,
    /// See [`Unwrapped::env_loss`].
    env_loss: Option<String>,
}

/// The commands a simple command runs: itself after wrappers, plus the
/// script of `sh -c`/`bash -c`/`eval` parsed again.
fn expand(cmd: &SimpleCommand, inherited: &[String], depth: usize, out: &mut Vec<Run>) {
    let un = strip_wrappers(&cmd.words);
    let mut assigns = inherited.to_vec();
    assigns.extend(cmd.assignments.iter().cloned());
    assigns.extend(un.assigns);
    let words = un.words;
    if words.is_empty() {
        // An assignment statement, a lone redirection, or a wrapper with
        // no command: kept for the env and redirection rules.
        out.push(Run {
            words,
            assigns,
            env_loss: un.env_loss,
        });
        return;
    }
    let name = basename(&words[0]);
    if depth < 4 {
        let script = match name {
            "sh" | "bash" | "zsh" | "dash" | "ksh" => words
                .iter()
                .position(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('c'))
                .and_then(|i| words.get(i + 1))
                .cloned(),
            "eval" => Some(words[1..].join(" ")),
            _ => None,
        };
        if let Some(s) = script {
            for inner in shell::parse(&s) {
                expand(&inner, &assigns, depth + 1, out);
            }
        }
    }
    out.push(Run {
        words,
        assigns,
        env_loss: un.env_loss,
    });
}

/// A parsed `git` invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitCall {
    /// Values of `-c` and `--config-env`.
    pub config: Vec<String>,
    /// Subcommand.
    pub sub: Option<String>,
    /// Arguments after the subcommand.
    pub args: Vec<String>,
}

/// git global options that take a separate value.
const GIT_GLOBAL_WITH_VALUE: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--config-env",
    "--super-prefix",
    "--attr-source",
];

/// Parses `words` as a git invocation (`git ...` or `git-<sub> ...`).
#[must_use]
pub fn git_call(words: &[String]) -> Option<GitCall> {
    let first = basename(words.first()?);
    if let Some(sub) = first.strip_prefix("git-") {
        return Some(GitCall {
            config: Vec::new(),
            sub: Some(sub.to_owned()),
            args: words[1..].to_vec(),
        });
    }
    if first != "git" {
        return None;
    }
    let mut call = GitCall::default();
    let mut i = 1;
    while i < words.len() {
        let w = words[i].as_str();
        if w == "-c" || w == "--config-env" {
            if let Some(v) = words.get(i + 1) {
                call.config.push(v.clone());
            }
            i += 2;
            continue;
        }
        if let Some(v) = w.strip_prefix("--config-env=") {
            call.config.push(v.to_owned());
            i += 1;
            continue;
        }
        if GIT_GLOBAL_WITH_VALUE.contains(&w) {
            i += 2;
            continue;
        }
        if w.starts_with('-') {
            i += 1;
            continue;
        }
        call.sub = Some(w.to_owned());
        call.args = words[i + 1..].to_vec();
        break;
    }
    Some(call)
}

/// `-n` as a flag of `git commit`/`am`/`push` (R25), short-option
/// clusters included; values of options that take one are skipped. Short
/// options with a value: `short_value` (the value is the rest of the
/// cluster or the next word) and `short_glued` (an optional value, only as
/// the rest of the cluster: `-u[<mode>]`, `-S[<keyid>]`).
fn has_short_n(sub: &str, args: &[String]) -> bool {
    let (short_value, short_glued, long_value): (&str, &str, &[&str]) = match sub {
        "commit" => (
            "mFcCtU",
            "uS",
            &[
                "--message",
                "--unified",
                "--file",
                "--author",
                "--date",
                "--template",
                "--reuse-message",
                "--reedit-message",
                "--fixup",
                "--squash",
                "--cleanup",
                "--trailer",
                "--pathspec-from-file",
            ],
        ),
        "push" => (
            "o",
            "",
            &["--push-option", "--repo", "--receive-pack", "--exec"],
        ),
        "am" => (
            "Cp",
            "S",
            &[
                "--directory",
                "--exclude",
                "--include",
                "--resolvemsg",
                "--patch-format",
            ],
        ),
        _ => return false,
    };
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if a == "--" {
            break;
        }
        if a.starts_with("--") {
            if long_value.contains(&a) {
                i += 1;
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-') else {
            continue;
        };
        for (k, c) in cluster.char_indices() {
            if c == 'n' {
                return true;
            }
            if short_glued.contains(c) {
                break;
            }
            if short_value.contains(c) {
                if k + c.len_utf8() == cluster.len() {
                    i += 1;
                }
                break;
            }
        }
    }
    false
}

/// R25: `-c`/`--config-env` keys that remove or redirect the hooks.
fn dangerous_config_key(value: &str) -> bool {
    let key = value.split('=').next().unwrap_or(value).to_lowercase();
    key == "core.hookspath"
        || key.starts_with("core.hooks")
        || key.starts_with("include.")
        || key.starts_with("includeif.")
        || key.starts_with("alias.")
}

/// R26: `git config` writes of these keys ask.
fn config_key_asks(key: &str) -> bool {
    let key = key.to_lowercase();
    key.starts_with("core.hooks")
        || key == "core"
        || key.starts_with("include")
        || key.starts_with("alias")
}

/// R26: a `git config` call that writes a hook, include or alias key.
fn git_config_write(args: &[String]) -> Option<String> {
    const WRITE_SUBS: &[&str] = &["set", "unset", "rename-section", "remove-section", "edit"];
    const WRITE_FLAGS: &[&str] = &[
        "--add",
        "--replace-all",
        "--unset",
        "--unset-all",
        "--rename-section",
        "--remove-section",
        "--edit",
        "-e",
    ];
    const READ_FLAGS: &[&str] = &[
        "--get",
        "--get-all",
        "--get-regexp",
        "--get-urlmatch",
        "--list",
        "-l",
        "get",
        "list",
    ];
    const WITH_VALUE: &[&str] = &[
        "--file",
        "-f",
        "--blob",
        "--type",
        "--default",
        "--comment",
        "--value",
    ];
    let mut positionals = Vec::new();
    let mut write = false;
    let mut read = false;
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if WITH_VALUE.contains(&a) {
            i += 1;
            continue;
        }
        if WRITE_FLAGS.contains(&a) {
            write = true;
            continue;
        }
        if READ_FLAGS.contains(&a) {
            read = true;
            continue;
        }
        if a.starts_with('-') {
            continue;
        }
        if positionals.is_empty() && WRITE_SUBS.contains(&a) {
            write = true;
            continue;
        }
        positionals.push(a);
    }
    let edit = args
        .iter()
        .any(|a| a == "edit" || a == "--edit" || a == "-e");
    if edit {
        return Some("git config --edit can change core.hooksPath (R26)".into());
    }
    let write = write || (!read && positionals.len() >= 2);
    let key = positionals.first()?;
    (write && config_key_asks(key)).then(|| format!("git config writes {key} (R26)"))
}

/// Expands `~`, `$HOME`, `${HOME}` and the XDG variables at the start of
/// `word`, then makes it absolute against the cwd and removes `.`/`..`.
fn resolve_path(ctx: &Context, word: &str) -> PathBuf {
    let mut w = word.to_owned();
    if w == "~" || w.starts_with("~/") {
        w = format!("{}{}", ctx.home.display(), &w[1..]);
    }
    for (name, value) in &ctx.vars {
        for form in [format!("${{{name}}}"), format!("${name}")] {
            if let Some(rest) = w.strip_prefix(&form)
                && (rest.is_empty() || rest.starts_with('/'))
            {
                w = format!("{value}{rest}");
            }
        }
    }
    let p = Path::new(&w);
    let abs = if p.is_absolute() {
        p.to_owned()
    } else {
        ctx.cwd.join(p)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn lower(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

/// True when `path` is inside `dir`, or (for removals) `dir` is inside
/// `path`. Case-insensitive (APFS); a glob path compares its literal
/// prefix.
fn touches(path: &Path, dir: &Path, removal: bool) -> bool {
    let p = lower(path);
    let d = lower(dir);
    let inside = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
    if let Some(cut) = p.find(['*', '?', '[']) {
        let prefix = &p[..cut];
        return d.starts_with(prefix) || prefix.starts_with(&format!("{d}/")) || prefix == d;
    }
    inside(&p, &d) || (removal && inside(&d, &p))
}

/// The paths a command writes or removes, with `true` for removals.
fn write_targets(words: &[String]) -> Vec<(String, bool)> {
    let name = basename(&words[0]);
    let args = &words[1..];
    let positionals: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let all = |removal: bool| {
        positionals
            .iter()
            .map(|p| ((*p).clone(), removal))
            .collect::<Vec<_>>()
    };
    let target_dir = args
        .iter()
        .position(|a| a == "-t" || a == "--target-directory")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| {
            args.iter()
                .find_map(|a| a.strip_prefix("--target-directory=").map(str::to_owned))
        });
    match name {
        "rm" | "rmdir" | "unlink" | "shred" => all(true),
        "mv" => all(true),
        "truncate" | "touch" | "chmod" | "chown" | "chgrp" | "mkdir" | "tee" | "setfattr" => {
            all(false)
        }
        "cp" | "install" | "ln" | "rsync" => {
            let mut v: Vec<(String, bool)> = positionals
                .last()
                .map(|p| ((*p).clone(), false))
                .into_iter()
                .collect();
            v.extend(target_dir.map(|d| (d, false)));
            v
        }
        "sed" | "perl" => {
            let in_place = args.iter().any(|a| {
                a == "--in-place"
                    || a.starts_with("--in-place=")
                    || (a.starts_with('-') && !a.starts_with("--") && a[1..].starts_with('i'))
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && a.contains('i')
                        && name == "sed")
            });
            if in_place { all(false) } else { Vec::new() }
        }
        "dd" => args
            .iter()
            .filter_map(|a| a.strip_prefix("of=").map(|p| (p.to_owned(), false)))
            .collect(),
        "find" => {
            let acts = args.iter().any(|a| {
                matches!(
                    a.as_str(),
                    "-delete"
                        | "-exec"
                        | "-execdir"
                        | "-ok"
                        | "-okdir"
                        | "-fprint"
                        | "-fprintf"
                        | "-fls"
                )
            });
            if acts {
                args.iter()
                    .take_while(|a| !a.starts_with('-') && a.as_str() != "(" && a.as_str() != "!")
                    .map(|p| (p.clone(), true))
                    .collect()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

/// R25/R26 on one command after wrappers.
fn command_ruling(ctx: &Context, words: &[String], redirects: &[shell::Redirect]) -> Ruling {
    let mut ruling = Ruling::Allow;
    // Writes to tollgate's own dirs (R25); reads stay open (R96).
    let mut targets: Vec<(String, bool)> = redirects
        .iter()
        .filter(|r| r.writes_file())
        .map(|r| (r.target.clone(), false))
        .collect();
    if !words.is_empty() {
        targets.extend(write_targets(words));
    }
    for (t, removal) in &targets {
        let p = resolve_path(ctx, t);
        if let Some(dir) = ctx.protected.iter().find(|d| touches(&p, d, *removal)) {
            return Ruling::Deny(format!(
                "writes to tollgate's dir {} (R25); reads are allowed",
                dir.display()
            ));
        }
    }
    let Some(first) = words.first() else {
        return ruling;
    };
    let name = basename(first);
    // R26: removing or moving git lock files.
    if matches!(name, "rm" | "mv")
        && words[1..].iter().any(|a| {
            let a = a.replace('\\', "/");
            a.ends_with(".lock") && (a.contains("/.git/") || a.starts_with(".git/"))
        })
    {
        ruling = ruling.max(Ruling::Ask(format!(
            "{name} of a git lock file: a live git may hold it; check with tollgate doctor --repo . (R26, R39)"
        )));
    }
    let Some(call) = git_call(words) else {
        return ruling;
    };
    if let Some(v) = call.config.iter().find(|v| dangerous_config_key(v)) {
        return Ruling::Deny(format!(
            "git -c {v}: changes hooks, includes or aliases (R25)"
        ));
    }
    let Some(sub) = call.sub.as_deref() else {
        return ruling;
    };
    let args = &call.args;
    match sub {
        "send-pack" | "receive-pack" => {
            return Ruling::Deny(format!("git {sub} skips the pre-push gate (R25)"));
        }
        "replace" => {
            return Ruling::Deny("git replace changes which tree is checked (R12, R25)".into());
        }
        "symbolic-ref"
            if args
                .iter()
                .any(|a| a.to_lowercase().starts_with("refs/heads")) =>
        {
            return Ruling::Deny("git symbolic-ref on a branch (R10, R25)".into());
        }
        "update-ref"
            if args
                .iter()
                .any(|a| a.to_lowercase().starts_with("refs/remotes")) =>
        {
            return Ruling::Deny("git update-ref of a remote-tracking ref (R13, R25)".into());
        }
        "commit" | "am" | "push" if has_short_n(sub, args) => {
            return Ruling::Deny(format!("git {sub} -n skips the gate hooks (R25)"));
        }
        "branch" => {
            const MOVES: &[&str] = &["-m", "-M", "-c", "-C", "--move", "--copy"];
            let moves = args.iter().any(|a| {
                MOVES.contains(&a.as_str())
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && a[1..].chars().any(|c| "mMcC".contains(c)))
            });
            if moves {
                let target = args.iter().rev().find(|a| !a.starts_with('-'));
                if let Some(t) = target {
                    let branch = t.strip_prefix("refs/heads/").unwrap_or(t);
                    if ctx.full_refs.is_match(branch) {
                        return Ruling::Deny(format!(
                            "git branch rename/copy onto full ref {t}: use tollgate merge (R25)"
                        ));
                    }
                    ruling = ruling.max(Ruling::Ask(format!(
                        "git branch rename/copy to {t} moves a branch without a check (R26)"
                    )));
                }
            }
        }
        "config" => {
            if let Some(why) = git_config_write(args) {
                ruling = ruling.max(Ruling::Ask(why));
            }
        }
        _ => {}
    }
    ruling
}

/// Variables that decide where tollgate finds its host config, install
/// record and records, and which config files git reads (R8). Hooks take
/// their dirs from `install.json`, not from these; the guard still denies
/// setting them for git or tollgate, so a CLI check cannot run against a
/// planted state dir either.
const DIR_VARS: &[&str] = &[
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
];

/// The [`DIR_VARS`] name that assignment word `a` (`NAME=v`, `NAME+=v`)
/// sets.
fn sets_dir_var(a: &str) -> Option<&'static str> {
    let (name, _) = a.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    DIR_VARS.iter().find(|v| **v == name).copied()
}

/// A [`DIR_VARS`] name that run `r` sets for the rest of the shell: an
/// assignment statement (`HOME=/x;`) or `export`/`declare -x`/... with an
/// assignment.
fn shell_dir_var(r: &Run) -> Option<&'static str> {
    match r.words.first().map(|w| basename(w)) {
        None => r.assigns.iter().find_map(|a| sets_dir_var(a)),
        Some("export" | "declare" | "typeset" | "readonly" | "local") => {
            r.words[1..].iter().find_map(|a| sets_dir_var(a))
        }
        Some(_) => None,
    }
}

/// True when `words` runs git or tollgate.
fn runs_git_or_tollgate(ctx: &Context, words: &[String]) -> bool {
    words
        .first()
        .is_some_and(|w| git_call(words).is_some() || is_tollgate(ctx, w))
}

/// R25/R26 for a Bash command.
#[must_use]
pub fn bash_ruling(ctx: &Context, command: &str) -> Ruling {
    let norm = normalize(command);
    for (needle, why) in DENY_SUBSTRINGS {
        if norm.contains(needle) {
            return Ruling::Deny(format!("{why} (R25)"));
        }
    }
    if no_verify_abbrev(&norm) {
        return Ruling::Deny("an abbreviation of --no-verify skips the gate hooks (R25)".into());
    }
    let cmds = shell::parse(command);
    let runs: Vec<Vec<Run>> = cmds
        .iter()
        .map(|cmd| {
            let mut runs = Vec::new();
            expand(cmd, &[], 0, &mut runs);
            runs
        })
        .collect();
    // R8: HOME or XDG set for the rest of the shell counts for every git
    // and tollgate in the command (best effort: order is not followed).
    let shell_sets = runs.iter().flatten().find_map(shell_dir_var);
    let mut ruling = Ruling::Allow;
    // `cd <dir>` changes where later relative paths point (best effort).
    let mut here = ctx.clone();
    for (cmd, runs) in cmds.iter().zip(&runs) {
        if let [cd, dir] = cmd.words.as_slice()
            && cd == "cd"
        {
            here.cwd = resolve_path(&here, dir);
        }
        let ctx = &here;
        for (k, run) in runs.iter().enumerate() {
            if let Some(why) = &run.env_loss {
                return Ruling::Deny(format!("{why} (R25)"));
            }
            if runs_git_or_tollgate(ctx, &run.words)
                && let Some(var) = run
                    .assigns
                    .iter()
                    .find_map(|a| sets_dir_var(a))
                    .or(shell_sets)
            {
                return Ruling::Deny(format!(
                    "{var} set for git or tollgate changes which config and records tollgate uses (R8, R25)"
                ));
            }
            // Redirections belong to the outer command only.
            let redirects: &[shell::Redirect] = if k + 1 == runs.len() {
                &cmd.redirects
            } else {
                &[]
            };
            ruling = ruling.max(command_ruling(ctx, &run.words, redirects));
            if matches!(ruling, Ruling::Deny(_)) {
                return ruling;
            }
        }
    }
    ruling
}

/// git subcommands that can run a gate hook and wait (R28).
const WAITING_GIT: &[&str] = &[
    "commit",
    "merge",
    "rebase",
    "cherry-pick",
    "revert",
    "am",
    "pull",
    "push",
    "reset",
];

/// R28: true when the command runs a git command that can wait in a gate
/// hook, or `tollgate check|wait|merge`.
#[must_use]
pub fn needs_long_timeout(ctx: &Context, command: &str) -> bool {
    shell::parse(command).iter().any(|cmd| {
        let mut runs = Vec::new();
        expand(cmd, &[], 0, &mut runs);
        runs.iter().any(|run| {
            let w = &run.words;
            if w.is_empty() {
                return false;
            }
            if let Some(call) = git_call(w) {
                return call
                    .sub
                    .as_deref()
                    .is_some_and(|s| WAITING_GIT.contains(&s));
            }
            is_tollgate(ctx, &w[0])
                && w.get(1)
                    .is_some_and(|s| matches!(s.as_str(), "check" | "wait" | "merge"))
        })
    })
}

/// True when `word` names the tollgate binary.
#[must_use]
pub fn is_tollgate(ctx: &Context, word: &str) -> bool {
    if word == "tollgate" {
        return true;
    }
    let p = resolve_path(ctx, word);
    ctx.tollgate_names.iter().any(|n| Path::new(n) == p)
}

/// L8: a single simple command `tollgate install|uninstall|doctor|status`
/// (by PATH name or the installed copy), allowed while the gate is not
/// armed so it can be repaired from a session.
#[must_use]
pub fn is_repair_command(ctx: &Context, command: &str) -> bool {
    let cmds = shell::parse(command);
    let [cmd] = cmds.as_slice() else {
        return false;
    };
    if !cmd.assignments.is_empty()
        || !cmd.redirects.is_empty()
        || command.contains(['`', '$', ';', '&', '|', '\n'])
    {
        return false;
    }
    cmd.words.first().is_some_and(|w| is_tollgate(ctx, w))
        && cmd
            .words
            .get(1)
            .is_some_and(|s| matches!(s.as_str(), "install" | "uninstall" | "doctor" | "status"))
}

/// R26 and the R25 dir rule for Write/Edit/MultiEdit/NotebookEdit.
#[must_use]
pub fn file_ruling(ctx: &Context, file: &str) -> Ruling {
    let p = resolve_path(ctx, file);
    if lower(&p) == lower(&ctx.host_config) {
        return Ruling::Ask(format!(
            "edit of the tollgate host config {} (R26)",
            p.display()
        ));
    }
    if let Some(dir) = ctx.protected.iter().find(|d| touches(&p, d, false)) {
        return Ruling::Deny(format!(
            "write under tollgate's dir {} (R25, R26)",
            dir.display()
        ));
    }
    let comps: Vec<String> = p
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let file_name = comps.last().cloned().unwrap_or_default();
    if comps.len() >= 2
        && comps[comps.len() - 2] == ".claude"
        && file_name.starts_with("settings")
        && file_name.ends_with(".json")
    {
        return Ruling::Ask(format!(
            "edit of Claude Code settings {} (R26)",
            p.display()
        ));
    }
    if comps.iter().any(|c| c == ".git") {
        return Ruling::Ask(format!("write under .git/: {} (R26)", p.display()));
    }
    if comps.iter().any(|c| c == ".githooks") {
        return Ruling::Ask(format!("edit of a repo hook {} (R26)", p.display()));
    }
    if let Some(why) = super::repo_rules(&p) {
        return Ruling::Ask(why);
    }
    Ruling::Allow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::glob::{self, GlobOpts};

    fn ctx() -> Context {
        Context {
            cwd: "/w/repo".into(),
            home: "/h".into(),
            vars: vec![
                ("HOME".into(), "/h".into()),
                ("XDG_STATE_HOME".into(), "/h/.local/state".into()),
            ],
            protected: vec![
                "/h/.local/state/tollgate".into(),
                "/h/.local/share/tollgate".into(),
                "/h/.config/tollgate".into(),
            ],
            host_config: "/h/.config/tollgate/config.toml".into(),
            full_refs: glob::compile(
                &["main", "master", "integration/*"],
                GlobOpts {
                    case_insensitive: true,
                    literal_separator: false,
                },
            )
            .unwrap(),
            tollgate_names: vec!["/h/.local/share/tollgate/bin/tollgate".into()],
        }
    }

    fn deny(cmd: &str) -> bool {
        matches!(bash_ruling(&ctx(), cmd), Ruling::Deny(_))
    }

    fn ask(cmd: &str) -> bool {
        matches!(bash_ruling(&ctx(), cmd), Ruling::Ask(_))
    }

    #[test]
    fn deny_patterns_r25() {
        for cmd in [
            "git commit --no-verify -m x",
            "git commit -n -m x",
            "git commit -anm x",
            "git -C repo commit -am msg -n",
            "git push -n origin x",
            "git am -n a.patch",
            "git -c core.hooksPath=/dev/null commit -m x",
            "git -c CORE.HOOKSPATH=/x commit",
            "git -c include.path=/tmp/x commit",
            "git -c includeIf.gitdir:/x.path=/y status",
            "git -c alias.ci=commit ci",
            "git --config-env=core.hooksPath=X commit",
            "git --config-env core.hooksPath=X commit",
            "GIT_CONFIG_COUNT=0 git commit -m x",
            "env -i git commit",
            "env -u GIT_CONFIG_COUNT git commit",
            "unset GIT_CONFIG_KEY_0; git commit",
            "export GIT_CONFIG_VALUE_0=/x",
            "git send-pack origin main",
            "/usr/bin/git receive-pack .",
            "git replace abc def",
            "git symbolic-ref refs/heads/alias refs/heads/src",
            "git update-ref refs/remotes/origin/main abc",
            "git branch -M x main",
            "git branch -m tmp MAIN",
            "git branch --copy feat integration/a",
            "tollgate waive --tree x",
            "tollgate policy approve HEAD",
            "tollgate baseline record pyright",
            "tee > ~/.local/state/tollgate/results/aa/x.json",
            "echo x > $HOME/.local/state/tollgate/x",
            "echo x >> ${XDG_STATE_HOME}/tollgate/x",
            "rm -rf ~/.local/state/tollgate",
            "rm -rf ~/.local/state",
            "rm ~/.local/state/tollgate/*",
            "mv ~/.local/share/tollgate/hooks /tmp/x",
            "cp evil ~/.local/share/tollgate/bin/tollgate",
            "sed -i s/a/b/ ~/.config/tollgate/config.toml",
            "truncate -s0 /h/.local/state/tollgate/toolcache.json",
            "cd /h/.local/state && rm -rf tollgate",
            "bash -c 'git commit -n -m x'",
            "sudo -u me git push -n",
            "echo $(git commit -n)",
            "find ~/.local/state/tollgate -name '*.json' -delete",
            "TOLLGATE_TEST_INSTALL=1 tollgate install --yes",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// git's option parser takes any unambiguous prefix of a long option:
    /// `--no-veri` is `--no-verify` for commit and push, `--no-v` for am.
    #[test]
    fn no_verify_abbreviations_deny_r25() {
        for cmd in [
            "git commit --no-verif -m x",
            "git commit --no-veri -m x",
            "git push --no-ver origin feat",
            "git push --no-veri origin HEAD:refs/heads/f",
            "git am --no-v a.patch",
            "git am --no-ve a.patch",
            "git merge --no-veri feat",
            "git commit -m x $'--no-verif'",
            "bash -c 'git commit --no-ver''if -m x'",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        assert_eq!(
            bash_ruling(&ctx(), "git commit --no-verbose -m x"),
            Ruling::Allow
        );
        assert_eq!(
            bash_ruling(&ctx(), "wget --no-verbose https://example.invalid/x"),
            Ruling::Allow
        );
    }

    /// Every way `env` and `exec` start a command with an empty
    /// environment drops the hook injection (R25).
    #[test]
    fn cleared_environments_deny_r25() {
        for cmd in [
            "env --ignore-environment PATH=/usr/bin git commit -m x",
            "env --ignore-env PATH=/usr/bin git commit -m x",
            "env --ign PATH=/usr/bin git status",
            "env - PATH=/usr/bin git commit -m x",
            "env -- - git commit -m x",
            "env -vi git commit -m x",
            "env -C /tmp -0i git status",
            "env -S '-i git commit -m x'",
            "env -vS'-i git commit -m x'",
            "env --split-string='-i git commit -m x'",
            "env -S 'git commit -n -m x'",
            "env --env0-from=/tmp/e git commit -m x",
            "exec -c git commit -m x",
            "exec -lc git commit -m x",
            "exec -a name -c git commit -m x",
            "bash -c 'exec -c git commit -m x'",
            "nohup env - git push origin feat",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "env -u FOO git status",
            "env FOO=1 git status",
            "env -C /w git status",
            "env --chdir=/w git status",
            "env --ignore-signal=PIPE git status",
            "env -a name git status",
            "exec git status",
            "exec -a name git status",
            "env",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    /// HOME, XDG and git's config-file variables set for git or tollgate
    /// are denied; the same for other programs stays allowed (R8, R25).
    #[test]
    fn dir_variables_in_front_of_git_deny_r8_r25() {
        for cmd in [
            "HOME=/tmp/x git commit -m x",
            "XDG_CONFIG_HOME=/tmp/c git commit -m x",
            "XDG_STATE_HOME=/tmp/s git push origin feat",
            "XDG_DATA_HOME=/tmp/d tollgate check",
            "env HOME=/tmp/x git commit -m x",
            "export HOME=/tmp/x; git commit -m x",
            "HOME=/tmp/x; git commit -m x",
            "declare -x XDG_STATE_HOME=/tmp/s && git push",
            "HOME=/tmp/x bash -c 'git commit -m x'",
            "bash -c 'export HOME=/tmp/x; git commit -m x'",
            "GIT_CONFIG_GLOBAL=/tmp/g git push origin feat",
            "GIT_CONFIG_SYSTEM=/tmp/g git commit -m x",
            "GIT_CONFIG_NOSYSTEM=1 git commit -m x",
            "HOME+=/x git status",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "HOME=/tmp/x cargo test",
            "export HOME=/tmp/x && cargo test",
            "XDG_STATE_HOME=/tmp/s bun test",
            "GIT_AUTHOR_NAME=a git status",
            "export HOME",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    /// `-u[<mode>]` and `-S[<keyid>]` take a value glued to the flag; an
    /// `n` in it is not `-n` (R25).
    #[test]
    fn optional_values_are_not_short_n_r25() {
        for cmd in [
            "git commit -uno -m x",
            "git commit -Snone -m x",
            "git commit -aSnokey -m x",
            "git commit -U5 -m x",
            "git am -Snone a.patch",
            "git am -C n a.patch",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        for cmd in [
            "git commit -un -n -m x",
            "git commit -vn -m x",
            "git am -kn a.patch",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    #[test]
    fn allowed_commands_r25() {
        for cmd in [
            "grep FAIL ~/.local/state/tollgate/jobs/J/tests.log",
            "cat /h/.local/state/tollgate/jobs/x/report.json | head",
            "tail -n 50 ~/.local/state/tollgate/jobs/J/clippy.log",
            "git commit -m 'fix -n handling'",
            "git commit -m -n",
            "git commit -F msg.txt",
            "git log -n 3",
            "git push origin feat",
            "git branch -d old",
            "git branch new",
            "ls -la",
            "cp ~/.local/state/tollgate/jobs/J/report.json /tmp/r.json",
            "git -C /w/other status",
            "git config --get core.hooksPath",
            "git config core.hooksPath",
            "tollgate check --tier full --rev HEAD --detach",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    #[test]
    fn ask_patterns_r26() {
        for cmd in [
            "git config core.hooksPath .githooks",
            "git config --global alias.ci commit",
            "git config set include.path /x",
            "git config --unset core.hooksPath",
            "git branch -m old new",
            "git branch -C a b",
            "rm .git/index.lock",
            "rm -f /w/repo/.git/worktrees/x/index.lock",
        ] {
            assert!(ask(cmd), "{cmd}");
        }
    }

    #[test]
    fn file_rules_r26() {
        let c = ctx();
        assert!(matches!(
            file_ruling(&c, "/h/.local/state/tollgate/results/x.json"),
            Ruling::Deny(_)
        ));
        assert!(matches!(
            file_ruling(&c, "/h/.local/share/tollgate/install.json"),
            Ruling::Deny(_)
        ));
        assert!(matches!(
            file_ruling(&c, "/h/.config/tollgate/config.toml"),
            Ruling::Ask(_)
        ));
        assert!(matches!(
            file_ruling(&c, "/h/.claude/settings.json"),
            Ruling::Ask(_)
        ));
        assert!(matches!(
            file_ruling(&c, "/w/repo/.claude/settings.local.json"),
            Ruling::Ask(_)
        ));
        assert!(matches!(file_ruling(&c, ".git/config"), Ruling::Ask(_)));
        assert!(matches!(
            file_ruling(&c, ".githooks/pre-commit"),
            Ruling::Ask(_)
        ));
        assert_eq!(file_ruling(&c, "src/main.rs"), Ruling::Allow);
    }

    #[test]
    fn long_timeout_trigger_r28() {
        let c = ctx();
        for cmd in [
            "git commit -m x",
            "cd r && git push origin feat",
            "git -C r rebase main",
            "tollgate check --wait",
            "/h/.local/share/tollgate/bin/tollgate merge feat",
            "git cherry-pick abc",
        ] {
            assert!(needs_long_timeout(&c, cmd), "{cmd}");
        }
        for cmd in [
            "ls",
            "git status",
            "git log",
            "tollgate status",
            "echo git commit",
        ] {
            assert!(!needs_long_timeout(&c, cmd), "{cmd}");
        }
    }

    #[test]
    fn repair_commands_l8() {
        let c = ctx();
        assert!(is_repair_command(&c, "tollgate install"));
        assert!(is_repair_command(&c, "tollgate doctor --injection"));
        assert!(is_repair_command(
            &c,
            "~/.local/share/tollgate/bin/tollgate status"
        ));
        assert!(!is_repair_command(&c, "tollgate install; git commit -m x"));
        assert!(!is_repair_command(&c, "tollgate check"));
        assert!(!is_repair_command(&c, "cd x && tollgate doctor"));
        assert!(!is_repair_command(&c, "tollgate doctor $(git commit -n)"));
        assert!(!is_repair_command(&c, "git status"));
    }

    #[test]
    fn normalization_r25() {
        assert_eq!(
            normalize("Git  COMMIT \"--No-Verify\"\n x"),
            "git commit --no-verify x"
        );
        assert_eq!(
            normalize("git commit --no\\-verify"),
            "git commit --no-verify"
        );
    }
}
