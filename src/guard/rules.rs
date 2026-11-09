//! The guard's text rules (R25 deny, R26 ask, R28 rewrite trigger).
//!
//! Two layers:
//!
//! - Substring rules on the normalized text (lowercase, quotes and
//!   backslashes removed, whitespace collapsed): they see everything but
//!   a few exact forms of data (literal commit messages, item 42; the body
//!   of `cat > <plain path> <<'QUOTED'` and `grep`/`rg` patterns, item
//!   51, [`data_spans`]), and err toward deny.
//! - Word rules on the parsed simple commands ([`super::shell`]), after
//!   wrappers (`env`, `sudo`, `xargs`, `bash -c`, ...) are stripped: git
//!   flags (`-n`, `-c <key>`), git subcommands, branch renames, and writes
//!   to tollgate's dirs.

use std::path::{Component, Path, PathBuf};

use globset::GlobSet;

use super::data;
use super::shell::{self, SimpleCommand};

/// Why a rule matched: a stable rule id for the metrics log (item 50)
/// and the text the agent sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Stable id (`no-verify`, `interpreter-stdin`, ...). It never holds
    /// text from the tool call.
    pub rule: &'static str,
    /// The message.
    pub text: String,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}

/// The guard's verdict on one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ruling {
    /// No rule matched.
    Allow,
    /// `permissionDecision: "ask"` with this reason (R26).
    Ask(Reason),
    /// Exit 2 with this reason (R25).
    Deny(Reason),
}

impl Ruling {
    /// A deny by rule `rule`.
    pub fn deny(rule: &'static str, text: impl Into<String>) -> Self {
        Self::Deny(Reason {
            rule,
            text: text.into(),
        })
    }

    /// An ask by rule `rule`.
    pub fn ask(rule: &'static str, text: impl Into<String>) -> Self {
        Self::Ask(Reason {
            rule,
            text: text.into(),
        })
    }

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

/// R25 substrings that deny wherever they appear: (needle, rule id, why).
const DENY_SUBSTRINGS: &[(&str, &str, &str)] = &[
    (
        "--no-verify",
        "no-verify",
        "--no-verify skips the gate hooks",
    ),
    (
        "git_config_count",
        "git-config-env",
        "GIT_CONFIG_* carries the hook injection",
    ),
    (
        "git_config_key",
        "git-config-env",
        "GIT_CONFIG_* carries the hook injection",
    ),
    (
        "git_config_value",
        "git-config-env",
        "GIT_CONFIG_* carries the hook injection",
    ),
    (
        "git_config_parameters",
        "git-config-parameters",
        "GIT_CONFIG_PARAMETERS overrides git config",
    ),
    ("env -i", "env-i", "env -i drops the hook injection"),
    (
        "env -u git",
        "env-u-git",
        "env -u GIT_* drops the hook injection",
    ),
    (
        "unset git_config",
        "unset-git-config",
        "unset GIT_CONFIG_* drops the hook injection",
    ),
    (
        "export git_config",
        "export-git-config",
        "export GIT_CONFIG_* changes the hook injection",
    ),
    (
        "tollgate waive",
        "tollgate-waive",
        "tollgate waive is not for agents",
    ),
    (
        "tollgate policy approve",
        "policy-approve",
        "policy approval is not for agents",
    ),
    (
        "tollgate baseline record",
        "baseline-record",
        "baseline record needs Victor's terminal (R94)",
    ),
    // L10: the test switch of `install --yes` is not for sessions.
    (
        "tollgate_test_install",
        "test-install",
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

/// The R25 substring and `--no-verify` abbreviation rules on normalized
/// text.
fn text_ruling(norm: &str) -> Option<Ruling> {
    if let Some((_, rule, why)) = DENY_SUBSTRINGS.iter().find(|(n, _, _)| norm.contains(n)) {
        return Some(Ruling::deny(rule, format!("{why} (R25)")));
    }
    no_verify_abbrev(norm).then(|| {
        Ruling::deny(
            "no-verify-abbrev",
            "an abbreviation of --no-verify skips the gate hooks (R25)",
        )
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
    /// The command words of the stripped wrappers, in order, as written.
    pub wrappers: Vec<String>,
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
        out.wrappers.push(first.clone());
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

/// Where a command's stdin comes from, besides the shell's own (item 31).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Feed {
    /// A pipe.
    piped: bool,
    /// A heredoc or a here-string.
    inline_doc: bool,
    /// A here-string (`<<<`).
    here_string: bool,
    /// Another input redirection (`<`, `<&`, `<>`).
    input: bool,
}

impl Feed {
    fn of(cmd: &SimpleCommand) -> Self {
        let op = |ops: &[&str]| cmd.redirects.iter().any(|r| ops.contains(&r.op.as_str()));
        Self {
            piped: cmd.piped,
            inline_doc: op(&["<<", "<<<"]),
            here_string: op(&["<<<"]),
            input: op(&["<", "<&", "<>"]),
        }
    }
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
    /// The simple command it came from, wrappers and their arguments
    /// included, as bash passes the words (quotes and escapes decoded).
    source: Vec<String>,
    /// Where its stdin comes from.
    feed: Feed,
    /// It is the own run of a top-level command each of whose words bash
    /// passes as written (`data::expands_nothing` on its source text), in
    /// a command with no extglob-like text and no `>(...)`
    /// ([`literal_runs`]); a word bash expands can be an option (`$opt`,
    /// `-$X`, `-{C,}`, `~`, `-@(C)`) the guard cannot see (item 51,
    /// security review). False until [`literal_runs`] sets it.
    literal: bool,
    /// Its heredoc bodies and here-strings: the text when the command
    /// gets it as written ([`shell::Redirect::literal`]), `None` when bash
    /// expands something in it.
    docs: Vec<Option<String>>,
}

/// The commands `find` runs: the words after each `-exec`, `-execdir`,
/// `-ok` or `-okdir` up to its `;` or `+`.
fn find_commands(args: &[String]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if matches!(a.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
            let sub: Vec<String> = it
                .by_ref()
                .take_while(|w| !matches!(w.as_str(), ";" | "+"))
                .cloned()
                .collect();
            if !sub.is_empty() {
                out.push(sub);
            }
        }
    }
    out
}

/// The commands a simple command runs: itself after wrappers, plus the
/// text it runs as shell code parsed again (`sh -c`, `eval`, `alias`, a
/// literal heredoc read by a shell) and the command of `find -exec`.
fn expand(cmd: &SimpleCommand, inherited: &[String], depth: usize, out: &mut Vec<Run>) {
    let un = strip_wrappers(&cmd.words);
    let mut assigns = inherited.to_vec();
    assigns.extend(cmd.assignments.iter().cloned());
    assigns.extend(un.assigns);
    let words = un.words;
    let source: Vec<String> = cmd.assignments.iter().chain(&cmd.words).cloned().collect();
    let feed = Feed::of(cmd);
    let literal = false;
    let docs: Vec<Option<String>> = cmd
        .redirects
        .iter()
        .filter_map(|r| match r.op.as_str() {
            "<<" => Some(r.literal.then(|| r.body.clone().unwrap_or_default())),
            "<<<" => Some(r.literal.then(|| r.target.clone())),
            _ => None,
        })
        .collect();
    if words.is_empty() {
        // An assignment statement, a lone redirection, or a wrapper with
        // no command: kept for the env and redirection rules.
        out.push(Run {
            words,
            assigns,
            env_loss: un.env_loss,
            source,
            feed,
            docs,
            literal,
        });
        return;
    }
    let name = basename(&words[0]);
    if depth < 4 {
        // Text bash runs as commands: the script of `sh -c`, `eval`'s
        // words, an `alias` value (item 51) and a heredoc or here-string
        // a shell reads as written (item 51; one that expands is text the
        // guard cannot read, see [`unseen_shell_text`]).
        let mut scripts: Vec<String> = Vec::new();
        match name {
            "sh" | "bash" | "zsh" | "dash" | "ksh" => scripts.extend(
                words
                    .iter()
                    .position(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('c'))
                    .and_then(|i| words.get(i + 1))
                    .cloned(),
            ),
            "eval" => scripts.push(words[1..].join(" ")),
            "alias" => scripts.extend(
                words[1..]
                    .iter()
                    .filter_map(|a| a.split_once('=').map(|(_, v)| v.to_owned())),
            ),
            _ => {}
        }
        if SHELLS.contains(&name) {
            scripts.extend(docs.iter().flatten().cloned());
        }
        for s in &scripts {
            for inner in shell::parse(s) {
                expand(&inner, &assigns, depth + 1, out);
            }
        }
        // The command `find -exec` (and its kin) runs (item 51).
        if name == "find" {
            for sub in find_commands(&words[1..]) {
                let inner = SimpleCommand {
                    words: sub,
                    ..SimpleCommand::default()
                };
                expand(&inner, &assigns, depth + 1, out);
            }
        }
    }
    out.push(Run {
        words,
        assigns,
        env_loss: un.env_loss,
        source,
        feed,
        docs,
        literal,
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

/// R26: `git config` writes of these keys ask. `url.*` rewrites
/// (`insteadOf`, `pushInsteadOf`) change which server a remote reaches,
/// which decides remote trust (R5, R14); `core.sshCommand`,
/// `core.gitProxy` and `ssh.*` change the program that reaches it (X1).
fn config_key_asks(key: &str) -> bool {
    let key = key.to_lowercase();
    key.starts_with("core.hooks")
        || key == "core"
        || key == "core.sshcommand"
        || key == "core.gitproxy"
        || key == "ssh"
        || key.starts_with("ssh.")
        || key.starts_with("include")
        || key.starts_with("alias")
        || key == "url"
        || key.starts_with("url.")
}

/// R26: a `git config` call that writes a key [`config_key_asks`] names.
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
            return Ruling::deny(
                "state-dir-write",
                format!(
                    "writes to tollgate's dir {} (R25); reads are allowed",
                    dir.display()
                ),
            );
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
        ruling = ruling.max(Ruling::ask("git-lock-file", format!(
            "{name} of a git lock file: a live git may hold it; check with tollgate doctor --repo . (R26, R39)"
        )));
    }
    let Some(call) = git_call(words) else {
        return ruling;
    };
    if let Some(v) = call.config.iter().find(|v| dangerous_config_key(v)) {
        return Ruling::deny(
            "git-c-hooks",
            format!("git -c {v}: changes hooks, includes or aliases (R25)"),
        );
    }
    if let Some(v) = call
        .config
        .iter()
        .find(|v| v.to_lowercase().starts_with("url."))
    {
        ruling = ruling.max(Ruling::ask(
            "git-c-url",
            format!("git -c {v}: rewrites remote URLs, which decide remote trust (R26, R5, R14)"),
        ));
    }
    let Some(sub) = call.sub.as_deref() else {
        return ruling;
    };
    let args = &call.args;
    match sub {
        "send-pack" | "receive-pack" => {
            return Ruling::deny(
                "git-pack-direct",
                format!("git {sub} skips the pre-push gate (R25)"),
            );
        }
        "replace" => {
            return Ruling::deny(
                "git-replace",
                "git replace changes which tree is checked (R12, R25)",
            );
        }
        "symbolic-ref"
            if args
                .iter()
                .any(|a| a.to_lowercase().starts_with("refs/heads")) =>
        {
            return Ruling::deny(
                "git-symbolic-ref",
                "git symbolic-ref on a branch (R10, R25)",
            );
        }
        "update-ref"
            if args
                .iter()
                .any(|a| a.to_lowercase().starts_with("refs/remotes")) =>
        {
            return Ruling::deny(
                "git-update-ref-remote",
                "git update-ref of a remote-tracking ref (R13, R25)",
            );
        }
        "commit" | "am" | "push" if has_short_n(sub, args) => {
            return Ruling::deny(
                "git-short-n",
                format!("git {sub} -n skips the gate hooks (R25)"),
            );
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
                        return Ruling::deny(
                            "branch-move-full",
                            format!(
                                "git branch rename/copy onto full ref {t}: use tollgate merge (R25)"
                            ),
                        );
                    }
                    ruling = ruling.max(Ruling::ask(
                        "branch-move",
                        format!(
                            "git branch rename/copy to {t} moves a branch without a check (R26)"
                        ),
                    ));
                }
            }
        }
        "config" => {
            if let Some(why) = git_config_write(args) {
                ruling = ruling.max(Ruling::ask("git-config-write", why));
            }
        }
        _ => {}
    }
    ruling
}

/// Why a dir variable is denied (R8).
const DIR_WHY: &str = "changes which config and records tollgate uses (R8, R25)";

/// Why a transport variable is denied (X1).
const TRANSPORT_WHY: &str = "picks the program git reaches a server with, which could answer for the trusted remote (X1, R25)";

/// Variables the guard denies for git and tollgate, with why:
///
/// - where tollgate finds its host config, install record and records,
///   and which config files git reads (R8). Hooks take their dirs from
///   `install.json`, not from these; the guard still denies them, so a CLI
///   check cannot run against a planted state dir either;
/// - the program git reaches a server with (`GIT_SSH*`,
///   `GIT_PROXY_COMMAND`) and the dir git runs its own programs from,
///   which git also puts first on the hooks' PATH (`GIT_EXEC_PATH`). The
///   trusted-server query (L2, R14(2), R56) runs in its own environment
///   anyway; the guard keeps them away from every git (X1).
const GUARDED_VARS: &[(&str, &str)] = &[
    ("HOME", DIR_WHY),
    ("XDG_CONFIG_HOME", DIR_WHY),
    ("XDG_STATE_HOME", DIR_WHY),
    ("XDG_DATA_HOME", DIR_WHY),
    ("GIT_CONFIG_GLOBAL", DIR_WHY),
    ("GIT_CONFIG_SYSTEM", DIR_WHY),
    ("GIT_CONFIG_NOSYSTEM", DIR_WHY),
    ("GIT_SSH", TRANSPORT_WHY),
    ("GIT_SSH_COMMAND", TRANSPORT_WHY),
    ("GIT_SSH_VARIANT", TRANSPORT_WHY),
    ("GIT_PROXY_COMMAND", TRANSPORT_WHY),
    (
        "GIT_EXEC_PATH",
        "changes which git programs git and the gate hooks run (X1, R25)",
    ),
];

/// The [`GUARDED_VARS`] entry that assignment word `a` (`NAME=v`,
/// `NAME+=v`) sets.
fn sets_guarded_var(a: &str) -> Option<(&'static str, &'static str)> {
    let (name, _) = a.split_once('=')?;
    let name = name.strip_suffix('+').unwrap_or(name);
    GUARDED_VARS.iter().find(|(v, _)| *v == name).copied()
}

/// A [`GUARDED_VARS`] entry that run `r` sets for the rest of the shell:
/// an assignment statement (`HOME=/x;`) or `export`/`declare -x`/... with
/// an assignment.
fn shell_guarded_var(r: &Run) -> Option<(&'static str, &'static str)> {
    match r.words.first().map(|w| basename(w)) {
        None => r.assigns.iter().find_map(|a| sets_guarded_var(a)),
        Some("export" | "declare" | "typeset" | "readonly" | "local") => {
            r.words[1..].iter().find_map(|a| sets_guarded_var(a))
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

/// True when `name` is in `text` in a form that can be the program: not
/// inside a longer word (`github`, `digit`, `.gitignore`, `tollgate.toml`)
/// and not a directory part (`state/tollgate/x`). `.git/` stays a mention:
/// it is the repo's own dir, hooks included.
fn names_program(text: &str, name: &str) -> usize {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    text.match_indices(name)
        .filter(|(at, _)| {
            let before = text[..*at].chars().next_back();
            let after = text[*at + name.len()..].chars().next();
            !(before.is_some_and(|c| word(c) || c == '-')
                || after.is_some_and(|c| word(c) || c == '.')
                || (after == Some('/') && before != Some('.'))
                // `git-commit` is git; `tollgate-core2` is a checkout's name.
                || (name == "tollgate" && after == Some('-')))
        })
        .count()
}

/// True when `text` has `cd <dir>` spelled out as its own words. A target
/// written any other way (quotes, escapes, a line continuation) is not
/// found, so its name still counts as a mention.
fn plain_cd(text: &str, dir: &str) -> bool {
    let wanted = format!("cd {dir}");
    text.match_indices(&wanted).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + wanted.len()..].chars().next();
        before.is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '('))
            && after.is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | ')'))
    })
}

/// True when the command text names git or tollgate as a program: in the
/// raw text or the normalized text (quotes and backslashes inside the name
/// do not hide it), heredoc bodies and messages included. The target of a
/// plain `cd` is a place, not a program: names are counted, and only a
/// count above what the `cd` targets account for is a mention. The text is
/// never edited, so a target cannot delete part of another word
/// (`printf 'git push' | sh; cd g`).
fn mentions_git_or_tollgate(command: &str, cmds: &[SimpleCommand]) -> bool {
    let raw = command.to_lowercase();
    let norm = normalize(command);
    let dirs: Vec<String> = cmds
        .iter()
        .filter_map(|cmd| match cmd.words.as_slice() {
            [cd, dir] if cd == "cd" => Some(dir.to_lowercase()),
            _ => None,
        })
        .filter(|dir| plain_cd(&raw, dir))
        .collect();
    ["git", "tollgate"].iter().any(|n| {
        let places: usize = dirs.iter().map(|dir| names_program(dir, n)).sum();
        names_program(&raw, n) > places || names_program(&norm, n) > places
    })
}

/// Shells, and the builtins that run a file as shell code, whose stdin
/// can be a script.
const SHELLS: &[&str] = &[
    "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "fish", "busybox", "source", ".",
];

/// How an interpreter takes its program on the command line, for one
/// question only: does it read its program from stdin? (Its program text
/// is every argument word, [`interpreter_text`]: options are not parsed
/// for it.)
struct InterpOptions {
    /// Short options whose value is the program (`python -c`, `perl -e`).
    code: &'static str,
    /// Long options whose value is the program (`--eval`).
    code_long: &'static [&'static str],
    /// Short options that take a value.
    valued: &'static str,
    /// Short options that take none.
    flags: &'static str,
    /// Its first operand is the program (`awk '...'`).
    operand_is_code: bool,
    /// It reads commands from stdin whatever its arguments (`ed`, `dc`,
    /// `sqlite3`).
    stdin_always: bool,
}

/// The interpreters the guard knows (item 51): their argument words can
/// be program text. Any other program that reads text (a heredoc, a
/// here-string, a pipe) is treated as one too, unless it is a
/// [`STDIN_DATA_READERS`] program ([`hidden_text`]).
fn interp_options(name: &str) -> Option<InterpOptions> {
    let o = |code, code_long, valued, flags, operand_is_code, stdin_always| InterpOptions {
        code,
        code_long,
        valued,
        flags,
        operand_is_code,
        stdin_always,
    };
    let any = |prefixes: &[&str]| prefixes.iter().any(|p| name.starts_with(p));
    if any(&["python", "pypy"]) {
        Some(o("cm", &[], "WXQ", "bBdEhiIOPqsSuvVx", false, false))
    } else if any(&["perl"]) {
        Some(o("eE", &[], "IMmxilCd0D", "acnpsStTuUvwWX", false, false))
    } else if any(&["ruby", "irb"]) {
        Some(o("e", &[], "IrCEFTKWx0", "acdhlnpsSvwy", false, false))
    } else if matches!(name, "node" | "nodejs" | "bun" | "deno") {
        Some(o("ep", &["--eval", "--print"], "rC", "hvic", false, false))
    } else if any(&["php"]) {
        Some(o("rBREf", &[], "cdzSt", "ahilmnqsvwHe", false, false))
    } else if any(&["lua"]) {
        Some(o("e", &[], "l", "iEvW", false, false))
    } else if any(&["awk", "gawk", "mawk", "nawk"]) {
        Some(o("", &["--source", "--file"], "fvF", "", true, false))
    } else if matches!(name, "ed" | "red" | "dc" | "sqlite3") {
        Some(o("", &[], "", "", false, true))
    } else if name == "R"
        || any(&[
            "Rscript",
            "tclsh",
            "wish",
            "expect",
            "julia",
            "pwsh",
            "powershell",
            "osascript",
            "guile",
            "racket",
            "jshell",
            "groovy",
            "scala",
            "elixir",
            "iex",
            "erl",
            "escript",
            "gdb",
        ])
    {
        Some(o("ce", &[], "", "", false, false))
    } else {
        None
    }
}

/// True when interpreter `o` with `args` reads its program from stdin:
/// no inline program and no script operand other than `-`. Fail closed:
/// after an option it does not know (which can take the next word as its
/// value), a later operand is not taken for the script.
fn reads_program_from_stdin(name: &str, o: &InterpOptions, args: &[String]) -> bool {
    if o.stdin_always {
        return true;
    }
    if name == "deno" {
        return args.is_empty() || args.iter().any(|a| a == "-");
    }
    let mut unsure = false;
    let mut i = 0;
    while let Some(a) = args.get(i) {
        i += 1;
        match a.as_str() {
            "-" => return true,
            "--" => return unsure || args.get(i).is_none_or(|s| s == "-"),
            _ => {}
        }
        if let Some(long) = a.strip_prefix("--") {
            let opt = long.split_once('=').map_or(long, |(o, _)| o);
            if o.code_long.contains(&format!("--{opt}").as_str()) {
                if opt == "file" {
                    // `awk --file -`.
                    let value = long
                        .split_once('=')
                        .map(|(_, v)| v.to_owned())
                        .or_else(|| args.get(i).cloned());
                    if value
                        .as_deref()
                        .is_some_and(|v| v == "-" || v == "/dev/stdin")
                    {
                        return true;
                    }
                }
                return unsure;
            }
            if !long.contains('=') {
                unsure = true;
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-') else {
            // The first operand: the script, or for awk the program.
            return unsure;
        };
        for (k, c) in cluster.char_indices() {
            let rest = &cluster[k + c.len_utf8()..];
            if o.code.contains(c) {
                return unsure;
            }
            if o.valued.contains(c) {
                let value = if rest.is_empty() {
                    i += 1;
                    args.get(i - 1).map(String::as_str)
                } else {
                    Some(rest)
                };
                // `awk -f -` reads its program from stdin.
                if o.operand_is_code && c == 'f' && matches!(value, Some("-" | "/dev/stdin")) {
                    return true;
                }
                if o.operand_is_code && c == 'f' {
                    return unsure;
                }
                break;
            }
            if !o.flags.contains(c) {
                unsure = true;
                break;
            }
        }
    }
    !o.operand_is_code || unsure
}

/// Programs whose stdin is data (item 51), with the exact short options
/// each may take: (flags, options that take a value). They run no line
/// of stdin and pass none of it to a program as an argument. Any other
/// option, short or long, makes the program an interpreter of its text,
/// since the guard does not read what each option does (security review,
/// 2026-11-09: `sort --compress-program` runs a program, `mapfile -C`
/// runs its callback as shell code). `git` takes any option: a message on
/// `-F -` is item 42's, a patch or a ref list is data.
const STDIN_DATA_READERS: &[(&str, &str, &str)] = &[
    ("cat", "nbsvETA", ""),
    ("tee", "a", ""),
    ("head", "qv0123456789", "nc"),
    ("tail", "qv0123456789", "nc"),
    ("wc", "lwcmL", ""),
    ("grep", "ivnclLhHEFGwxqsor", "eABCm"),
    ("egrep", "ivnclLhHwxqsor", "eABCm"),
    ("fgrep", "ivnclLhHwxqsor", "eABCm"),
    ("cut", "s", "dfcb"),
    ("tr", "dscC", ""),
    ("jq", "rcnsSje", ""),
    ("read", "rs", "pdnNta"),
    ("mapfile", "t", "dnOsu"),
    ("readarray", "t", "dnOsu"),
];

/// True when `name` with `args` reads its stdin as data
/// ([`STDIN_DATA_READERS`]): git, or a listed program whose every option
/// before `--` is one of its own (a value glued to or after a valued
/// option is skipped).
fn stdin_data_reader(name: &str, args: &[String]) -> bool {
    if name == "git" {
        return true;
    }
    let Some(&(_, flags, valued)) = STDIN_DATA_READERS.iter().find(|(n, _, _)| *n == name) else {
        return false;
    };

    let mut i = 0;
    while let Some(a) = args.get(i) {
        i += 1;
        if a == "--" {
            return true;
        }
        let Some(cluster) = a.strip_prefix('-') else {
            continue;
        };
        if cluster.is_empty() {
            continue;
        }
        if cluster.starts_with('-') {
            return false;
        }
        for (k, c) in cluster.char_indices() {
            if valued.contains(c) {
                if k + c.len_utf8() == cluster.len() {
                    i += 1;
                }
                break;
            }
            if !flags.contains(c) {
                return false;
            }
        }
    }
    true
}

/// True when run `r` reads its stdin as data: its program does
/// ([`stdin_data_reader`]) and no `xargs` or `parallel` in front of it
/// turns stdin into its arguments.
fn run_reads_data(r: &Run) -> bool {
    let wrappers = r.source.len().saturating_sub(r.words.len());
    r.literal
        && r.words
            .first()
            .is_some_and(|w| stdin_data_reader(basename(w), &r.words[1..]))
        && !r.source[..wrappers]
            .iter()
            .any(|w| matches!(basename(w), "xargs" | "parallel"))
}

/// True when `text` names git or tollgate as a program ([`names_program`]),
/// as written or without quotes and backslashes (they do not hide a name:
/// `g"i"t`). ASCII lowercase finds the same names as the Unicode one: no
/// other character lowercases to a run of these ASCII letters (L19: one
/// copy of a large heredoc each).
fn names_git_or_tollgate(text: &str) -> bool {
    let raw = text.to_ascii_lowercase();
    let names = |t: &str| ["git", "tollgate"].iter().any(|n| names_program(t, n) > 0);
    if names(&raw) {
        return true;
    }
    raw.contains(['\'', '"', '\\', '`'])
        && names(
            &raw.chars()
                .filter(|c| !matches!(c, '\'' | '"' | '\\' | '`'))
                .collect::<String>(),
        )
}

/// What a program of run `r` reads as code (item 51; the lead's
/// correction of 2026-11-09: there is no OS sandbox, so the guard is the
/// only layer), when `r` runs an interpreter or reads text.
struct CodeText {
    /// The program is a shell or a known interpreter ([`interp_options`]).
    interpreter: bool,
    /// It reads its program from stdin (always for a shell).
    from_stdin: bool,
    /// Text the guard can read: its literal heredocs and here-strings;
    /// for an interpreter every argument word (for a shell, all but its
    /// `-c` script, which is parsed as commands) and the assignments it
    /// sees (`env_text` too).
    texts: Vec<String>,
    /// It reads program text the guard cannot see: an input redirection,
    /// a heredoc or here-string that expands, or (for an interpreter) a
    /// pipe it reads its program from.
    unseen: bool,
    /// It reads a pipe or an input file: what the rest of the command
    /// prints can be its program, or code it runs (`awk '{system($0)}'`),
    /// see [`flow_text`].
    flow: bool,
}

/// The [`CodeText`] of run `r`; `None` for a program that reads its stdin
/// as data ([`stdin_data_reader`]), and for one that is no interpreter
/// and reads no text.
fn code_text(r: &Run, env_text: &[String]) -> Option<CodeText> {
    let first = r.words.first()?;
    let name = basename(first);
    let args = &r.words[1..];
    if run_reads_data(r) {
        return None;
    }
    let shell = SHELLS.contains(&name);
    let interp = interp_options(name);
    // `mapfile -C <callback>` runs the callback as shell code for lines
    // it reads: its words are code like an interpreter's.
    let callback = matches!(name, "mapfile" | "readarray")
        && (!r.literal
            || args
                .iter()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('C')));
    let interpreter = shell || interp.is_some() || callback;
    let Feed {
        piped,
        inline_doc,
        input,
        ..
    } = r.feed;
    if !(interpreter || piped || inline_doc || input) {
        return None;
    }
    let from_stdin = shell
        || interp
            .as_ref()
            .is_some_and(|o| reads_program_from_stdin(name, o, args));
    let mut texts: Vec<String> = r.docs.iter().flatten().cloned().collect();
    if shell {
        let script = args
            .iter()
            .position(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('c'))
            .map(|i| i + 1);
        texts.extend(
            args.iter()
                .enumerate()
                .filter(|(i, _)| Some(*i) != script)
                .map(|(_, a)| a.clone()),
        );
    } else if interpreter {
        texts.extend(args.iter().cloned());
    }
    if interpreter || inline_doc {
        texts.extend(r.assigns.iter().cloned());
        texts.extend(env_text.iter().cloned());
    }
    let expands = r.docs.iter().any(Option::is_none);
    Some(CodeText {
        interpreter,
        from_stdin,
        texts,
        unseen: input || expands || (interpreter && piped && from_stdin),
        flow: piped || input,
    })
}

/// Assignments a later program can see in its environment: bare
/// assignment statements and the words of `export`, `declare`, `typeset`,
/// `readonly` and `local` (item 51).
fn env_assignments(runs: &[Vec<Run>]) -> Vec<String> {
    runs.iter()
        .flatten()
        .flat_map(|r| match r.words.first().map(|w| basename(w)) {
            None => r.assigns.clone(),
            Some("export" | "declare" | "typeset" | "readonly" | "local") => r.words[1..].to_vec(),
            Some(_) => Vec::new(),
        })
        .collect()
}

/// Item 51 (security review, 2026-11-09, fail closed): the text that can
/// flow through a pipe or a file into a program: every argument word,
/// literal heredoc and here-string and assignment of the command's runs,
/// but those of a git or tollgate command (their output is not text the
/// command chose) and of `cd`. Any program can print its arguments
/// (`jq`, `grep -o`), so none is left out.
fn flow_text(ctx: &Context, runs: &[Vec<Run>]) -> Vec<String> {
    runs.iter()
        .flatten()
        .filter(|r| {
            !runs_git_or_tollgate(ctx, &r.words)
                && r.words.first().is_none_or(|w| basename(w) != "cd")
        })
        .flat_map(|r| {
            r.words
                .iter()
                .skip(1)
                .chain(r.docs.iter().flatten())
                .chain(&r.assigns)
                .cloned()
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Item 51: true when command word `word` may be git or tollgate although
/// it does not read as either: bash expands it (`$G`, `${G}`, a `$(...)`,
/// a backtick substitution, which leaves a blank in the word), a brace
/// list (`g{i,}t`), or a glob that can match a program name `git`,
/// `git-<x>` or `tollgate` (`/usr/bin/gi?`). A lone `*` is a `case`
/// pattern in practice (`*) ...;;`), and `[`/`[[` are tests.
fn hidden_program(word: &str) -> bool {
    if word.contains(['$', '`']) || word.contains(char::is_whitespace) {
        return true;
    }
    if word.contains('{') && word.contains('}') {
        return true;
    }
    if matches!(word, "*" | "[" | "[[") || !word.contains(['*', '?', '[']) {
        return false;
    }
    globset::Glob::new(basename(word)).map_or(true, |g| {
        let m = g.compile_matcher();
        ["git", "git-commit", "tollgate"]
            .iter()
            .any(|n| m.is_match(n))
    })
}

/// Item 51: true when run `r` changes which program a later command word
/// names: the command hash table (`hash -p`, `BASH_CMDS`), loaded
/// builtins (`enable`) or aliases set by assignment (`BASH_ALIASES`; an
/// `alias` value is parsed as commands by [`expand`]).
fn renames_programs(r: &Run) -> bool {
    let first = r.words.first().map(|w| basename(w));
    first == Some("enable")
        || first == Some("function")
        || (first == Some("hash")
            && r.words[1..]
                .iter()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('p')))
        || r.assigns
            .iter()
            .chain(&r.words)
            .any(|w| w.starts_with("BASH_CMDS") || w.starts_with("BASH_ALIASES"))
}

/// Item 51: a shell that reads text the guard cannot read: from a pipe,
/// an input redirection, or a heredoc or here-string that expands. A
/// heredoc or here-string it reads as written is parsed as its commands
/// ([`expand`]).
fn unseen_shell_text(runs: &[Vec<Run>]) -> bool {
    runs.iter().flatten().any(|r| {
        r.words
            .first()
            .is_some_and(|w| SHELLS.contains(&basename(w)))
            && (r.feed.piped || r.feed.input || r.docs.iter().any(Option::is_none))
    })
}

/// Item 51 (security review notes 2 and 3, 2026-11-09): true when the
/// command may run git or tollgate, read from the parsed command words
/// only: a command position after wrappers (`env`, `sudo`, `xargs`, ...),
/// in a substitution, a subshell, a function body, `sh -c`, `eval`, an
/// `alias` value, a heredoc or here-string a shell reads, or `find
/// -exec`, that is git or tollgate or may be one ([`hidden_program`]),
/// or a run that renames programs ([`renames_programs`]). Words inside
/// quotes, heredoc bodies and here-strings are data to the program that
/// gets them, so naming git there (a `cat` heredoc, a `grep` pattern)
/// does not count; an interpreter's program text is checked on its own
/// ([`hidden_text`]). Text a shell reads that the guard cannot see (a pipe,
/// an input file, an expanding heredoc) is the exception: it is the
/// shell's commands, so there any mention of git or tollgate counts, in
/// the raw text, the normalized text or the decoded words (`decoded`,
/// `cd` targets left out), as before item 51.
fn may_run_git_or_tollgate(
    ctx: &Context,
    command: &str,
    cmds: &[SimpleCommand],
    runs: &[Vec<Run>],
    decoded: &[String],
) -> bool {
    let named = runs.iter().flatten().any(|r| {
        renames_programs(r)
            || r.words
                .first()
                .is_some_and(|w| runs_git_or_tollgate(ctx, &r.words) || hidden_program(w))
    });
    named
        || unseen_shell_text(runs)
            && (mentions_git_or_tollgate(command, cmds)
                || decoded
                    .iter()
                    .filter(|d| !d.starts_with("cd "))
                    .any(|d| names_program(d, "git") > 0 || names_program(d, "tollgate") > 0))
}

/// Item 51, exemption 4 (the lead's direction of 2026-11-09): a python,
/// perl or other non-shell interpreter that reads its text from heredocs
/// only (no here-string, pipe or input file), whose bodies bash passes as
/// written and name none of git, tollgate, a guarded flag or a guarded
/// variable, in a command whose parsed words run no git or tollgate
/// (`runs_git`). Item 31 does not deny it for a mention of git elsewhere
/// in the command (a `grep git` next to it). A guarded flag or variable
/// in a body has denied the command already: the substring rules read
/// the whole command first, and an interpreter's body is never data
/// ([`data_spans`]).
fn clean_heredoc_program(r: &Run, runs_git: bool) -> bool {
    let Some(first) = r.words.first() else {
        return false;
    };
    let name = basename(first);
    let Feed {
        piped,
        inline_doc,
        here_string,
        input,
    } = r.feed;
    !runs_git
        && !SHELLS.contains(&name)
        && interp_options(name).is_some()
        && inline_doc
        && !(here_string || piped || input)
        && !r.docs.is_empty()
        && r.docs
            .iter()
            .all(|d| d.as_deref().is_some_and(|t| !names_git_or_tollgate(t)))
}

/// Item 31 (21c): in a command that names git or tollgate (its text
/// outside the item 51 `data` spans, or its parsed words: `runs_git`;
/// read only when a rule needs it, L19), text the
/// guard does not check is denied instead of decoded: ANSI-C quoting, a
/// `\c` escape, and text fed to an interpreter (a shell or one
/// [`interp_options`] knows) through a pipe it reads its program from, a
/// heredoc, a here-string or an input redirection, at any depth (`bash -c
/// '... | sh'` included), except a [`clean_heredoc_program`].
///
/// Item 51 (the lead's correction of 2026-11-09: there is no OS sandbox,
/// so the guard is the only layer): a program can start git itself
/// (`subprocess.run(['git', 'commit', '-n'])`), so its text is code, not
/// data, whatever the command's own words run. A program that runs an
/// interpreter or reads text is denied when the code it gets names git or
/// tollgate ([`code_text`]): the text the guard can read; the whole
/// command when it reads program text the guard cannot see, as item 31
/// did; and the [`flow_text`] when it reads a pipe or a file. Only a
/// program that reads its stdin as data ([`STDIN_DATA_READERS`]) is left
/// out. `plain` is the command without its literal messages (item 42)
/// and literal heredoc bodies, where the `\c` check does not look;
/// `decoded` are its decoded words.
#[allow(clippy::too_many_arguments)]
fn hidden_text(
    ctx: &Context,
    extglob: bool,
    data: &[(usize, usize)],
    runs_git: bool,
    plain: &str,
    ansi_c: bool,
    command: &str,
    cmds: &[SimpleCommand],
    runs: &[Vec<Run>],
    decoded: &[String],
) -> Option<Ruling> {
    let mut named: Option<bool> = None;
    let mut gate = || {
        *named.get_or_insert_with(|| {
            runs_git || mentions_git_or_tollgate(&blanked(command, data), cmds)
        })
    };
    if ansi_c && gate() {
        return Some(Ruling::deny(
            "ansi-c",
            "ANSI-C quoting ($'...') in a command that runs git or tollgate is not checked: write the words plainly, and give a multi-line commit message with -F <file> or a quoted heredoc (item 31, R25)",
        ));
    }
    if plain.contains("\\c") && gate() {
        return Some(Ruling::deny(
            "backslash-c",
            "a \\c escape in a command that runs git or tollgate is not checked; write the text without it (item 31, R25)",
        ));
    }
    if extglob && mentions_git_or_tollgate(command, cmds) {
        return Some(Ruling::deny(
            "extglob",
            "an extglob pattern (@(...), !(...), +(...), *(...), ?(...)) in a command that names git or tollgate is not checked; write the words plainly (item 51, R25)",
        ));
    }
    let env_text = env_assignments(runs);
    let mut anywhere: Option<bool> = None;
    let mut flows: Option<bool> = None;
    for run in runs.iter().flatten() {
        let Some(code) = code_text(run, &env_text) else {
            continue;
        };
        let name = basename(&run.words[0]);
        let Feed {
            piped,
            inline_doc,
            input,
            ..
        } = run.feed;
        if code.interpreter
            && (inline_doc || input || (piped && code.from_stdin))
            && !clean_heredoc_program(run, runs_git)
            && gate()
        {
            return Some(Ruling::deny(
                "interpreter-stdin",
                format!(
                    "{name} reads text from a pipe, heredoc or redirection in a command that runs git or tollgate; the guard cannot check that text, so run the commands directly (item 31, R25)"
                ),
            ));
        }
        let names = code.texts.iter().any(|t| names_git_or_tollgate(t))
            || code.unseen
                && *anywhere.get_or_insert_with(|| {
                    mentions_git_or_tollgate(command, cmds)
                        || decoded
                            .iter()
                            .filter(|d| !d.starts_with("cd "))
                            .any(|d| names_git_or_tollgate(d))
                })
            || code.flow
                && *flows.get_or_insert_with(|| {
                    flow_text(ctx, runs)
                        .iter()
                        .any(|t| names_git_or_tollgate(t))
                });
        if names {
            return Some(Ruling::deny(
                "interpreter-text",
                format!(
                    "{name} gets program text (an argument, heredoc, here-string, pipe or input file) that names git or tollgate; the guard does not check what that program runs (item 51, R25)"
                ),
            ));
        }
    }
    None
}

/// Programs that only read and print: their arguments are data, and they
/// start no other program ([`search_only`] handles `rg`'s options that do).
const SEARCH_PROGRAMS: &[&str] = &[
    "cd", "grep", "egrep", "fgrep", "rg", "cat", "head", "tail", "wc", "ls", "cut",
];

/// True when every command, substitutions included, is one of
/// [`SEARCH_PROGRAMS`], sets no variable, loses no environment, writes no
/// file and takes no inline text. The R25 text rules are about running or
/// setting a name; here the name is only what the command looks for.
fn search_only(cmds: &[SimpleCommand], runs: &[Vec<Run>]) -> bool {
    !cmds.is_empty()
        && cmds.iter().zip(runs).all(|(cmd, runs)| {
            !runs.is_empty()
                && cmd.assignments.is_empty()
                && !cmd
                    .redirects
                    .iter()
                    .any(|r| r.writes_file() || matches!(r.op.as_str(), "<<" | "<<-" | "<<<"))
                && runs.iter().all(|run| {
                    run.env_loss.is_none()
                        && run.assigns.is_empty()
                        && run.words.first().is_some_and(|w| {
                            let name = basename(w);
                            SEARCH_PROGRAMS.contains(&name)
                                && !(name == "rg"
                                    && run.words.iter().any(|a| {
                                        a.starts_with("--pre") || a.starts_with("--hostname-bin")
                                    }))
                        })
                })
        })
}

/// Item 42: `command` with the literal messages of its top-level `git
/// commit`, `git merge` and `git tag` commands blanked out
/// ([`data::message_words`]), and for each command the indices of its
/// words that were blanked. A message is blanked only when bash passes it
/// as written: a literal word, the `"$(cat <<'EOF' ... EOF)"` form, or the
/// body of a heredoc read by `-F -` whose delimiter is quoted or whose
/// body expands nothing.
///
/// With an editor git runs a program on the message file, so nothing is
/// blanked in a command that may start one: [`data::message_words`]
/// gives no words for an edit option, and the git call's
/// `-c`/`--config-env` must not set an editor ([`EDITOR_KEYS`]).
///
/// The message is data only while the program that gets it is the real
/// git with the words as written: the command word is bare `git` or a
/// [`SYSTEM_GITS`] path, its wrappers are [`PLAIN_WRAPPERS`], and nothing
/// in `command` (`runs` are all its runs) can change what `git` runs or
/// set an editor ([`git_can_change`]).
fn literal_messages(
    command: &str,
    cmds: &[SimpleCommand],
    runs: &[Vec<Run>],
) -> (String, Vec<Vec<usize>>) {
    let chars: Vec<char> = command.chars().collect();
    let mut blank: Vec<(usize, usize)> = Vec::new();
    let mut skipped = vec![Vec::new(); cmds.len()];
    for (cmd, skip) in cmds.iter().zip(&mut skipped) {
        if !cmd.top || cmd.spans.len() != cmd.words.len() {
            continue;
        }
        let un = strip_wrappers(&cmd.words);
        if !cmd.words.ends_with(&un.words)
            || !un
                .wrappers
                .iter()
                .all(|w| PLAIN_WRAPPERS.contains(&w.as_str()))
            || !un
                .words
                .first()
                .is_some_and(|w| w == "git" || SYSTEM_GITS.contains(&w.as_str()))
        {
            continue;
        }
        let Some(call) = git_call(&un.words) else {
            continue;
        };
        let Some(sub) = call.sub.as_deref() else {
            continue;
        };
        if call.config.iter().any(|c| {
            let key = c.split('=').next().unwrap_or(c).to_lowercase();
            EDITOR_KEYS.contains(&key.as_str())
        }) {
            continue;
        }
        let first_arg = cmd.words.len() - call.args.len();
        let msgs = data::message_words(sub, &call.args);
        // Every other word must reach git as written: one that expands
        // (`$E`, a glob) can be an edit option the reading never saw.
        let plain = cmd.spans.iter().enumerate().all(|(w, &(a, b))| {
            w.checked_sub(first_arg)
                .is_some_and(|i| msgs.words.contains(&i))
                || data::plain_word(
                    &chars[a..b].iter().collect::<String>(),
                    a.checked_sub(1).map(|k| chars[k]),
                    chars.get(b).copied(),
                )
        });
        if !plain {
            continue;
        }
        for i in msgs.words {
            let w = first_arg + i;
            let Some(&(a, b)) = cmd.spans.get(w) else {
                continue;
            };
            let raw: String = chars[a..b].iter().collect();
            let before = a.checked_sub(1).map(|k| chars[k]);
            let after = chars.get(b).copied();
            if data::literal_word(&raw, before, after)
                || data::cat_heredoc_word(&raw, before, after)
            {
                blank.push((a, b));
                skip.push(w);
            }
        }
        if msgs.stdin {
            blank.extend(
                cmd.redirects
                    .iter()
                    .filter(|r| r.op == "<<" && r.literal)
                    .filter_map(|r| r.body_span),
            );
        }
    }
    let mut rest = chars;
    blank_spans(&mut rest, &blank);
    let rest: String = rest.into_iter().collect();
    if !blank.is_empty() && git_can_change(&without_literal_docs(&rest, cmds), runs) {
        return (command.to_owned(), vec![Vec::new(); cmds.len()]);
    }
    (rest, skipped)
}

/// Absolute paths of the system git that a masked message may go to
/// (item 42); any other path can be a program the agent wrote.
const SYSTEM_GITS: &[&str] = &["/usr/bin/git", "/bin/git"];

/// Wrappers that run bare `git` with its words unchanged, found the same
/// way (item 42). `env` can set PATH or split words (`-S`), `xargs` adds
/// words, `exec`, `sudo` and the others change how or as whom git runs.
const PLAIN_WRAPPERS: &[&str] = &[
    "command", "nohup", "time", "timeout", "nice", "then", "do", "else", "elif", "if", "while",
    "until", "!",
];

/// Bash builtins and keywords that can set a variable, an alias, a
/// function, a shell option, a trap or the command hash table, or run
/// text as shell code. The other builtins (`:`, `true`, `false`, `echo`,
/// `pwd`, `cd`, `pushd`, `popd`, `dirs`, `test`, `[`, `type`, `help`,
/// `times`, `ulimit`, `umask`, `jobs`, `bg`, `fg`, `kill`, `disown`,
/// `suspend`, `logout`, `exit`, `return`, `break`, `continue`, `shift`,
/// `caller`, `command`, `builtin`, `exec`) change none of these;
/// `printf` and `wait` do only with an option (`-v`, `-p`).
const STATE_BUILTINS: &[&str] = &[
    ".",
    "source",
    "eval",
    "alias",
    "unalias",
    "shopt",
    "set",
    "hash",
    "enable",
    "trap",
    "declare",
    "typeset",
    "local",
    "readonly",
    "export",
    "unset",
    "read",
    "mapfile",
    "readarray",
    "getopts",
    "let",
    "fc",
    "history",
    "bind",
    "compgen",
    "complete",
    "compopt",
    "function",
    "coproc",
    "for",
    "select",
    "[[",
];

/// Item 42 recheck: true when Bash command `text` (its masked messages and
/// literal heredoc bodies blanked; `runs` are all its runs) can change
/// what its `git` runs or let an editor start, so a message it passes to
/// git can become code: a function definition (`git() { eval "$3"; }`),
/// an alias, the hash table (`hash -p`, `BASH_CMDS`), a loaded builtin, a
/// sourced file, a trap, or PATH, an [`EDITOR_VARS`] variable or a
/// `BASH*` variable set in any way. Arithmetic (`((`, `$((`, `$[`, `[[`,
/// `let`) and `${...}` can assign a variable whose name is computed, so
/// they count too.
fn git_can_change(text: &str, runs: &[Vec<Run>]) -> bool {
    let t: Vec<char> = text.chars().collect();
    let fn_def = t
        .iter()
        .enumerate()
        .any(|(i, &c)| c == '(' && t[i + 1..].iter().find(|c| !c.is_whitespace()) == Some(&')'));
    if fn_def || text.contains("((") || text.contains("$[") || text.contains("${") {
        return true;
    }
    let lookup_var = |a: &String| {
        let name = a.split(['=', '[', '+']).next().unwrap_or(a);
        name == "PATH"
            || name.starts_with("BASH")
            || EDITOR_VARS.contains(&name)
            || matches!(name, "ENV" | "SHELLOPTS" | "PS4")
    };
    runs.iter().flatten().any(|r| {
        r.assigns.iter().any(lookup_var)
            || r.words.first().is_some_and(|w| {
                w.contains('=')
                    || STATE_BUILTINS.contains(&w.as_str())
                    || matches!(w.as_str(), "printf" | "wait")
                        && r.words[1..]
                            .iter()
                            .any(|a| a.starts_with('-') || a.contains('$'))
            })
    })
}

/// Variables that name the program git runs as its editor.
const EDITOR_VARS: &[&str] = &["GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "VISUAL", "EDITOR"];

/// Config keys that name the program git runs as its editor.
const EDITOR_KEYS: &[&str] = &["core.editor", "sequence.editor"];

/// Replaces the chars of `spans` with blanks (newlines stay, so lines and
/// words never join).
fn blank_spans(chars: &mut [char], spans: &[(usize, usize)]) {
    for &(a, b) in spans {
        for c in &mut chars[a..b] {
            if *c != '\n' {
                *c = ' ';
            }
        }
    }
}

/// `text` (the command, messages blanked) without the bodies of its
/// top-level heredocs that bash passes as written. A `\c` there is a
/// character of a file or a message, not an escape any shell reads: a
/// body fed to a shell is denied on its own (item 31).
fn without_literal_docs(text: &str, cmds: &[SimpleCommand]) -> String {
    let mut chars: Vec<char> = text.chars().collect();
    let spans: Vec<(usize, usize)> = cmds
        .iter()
        .filter(|c| c.top)
        .flat_map(|c| &c.redirects)
        .filter(|r| r.op == "<<" && r.literal)
        .filter_map(|r| r.body_span)
        .collect();
    blank_spans(&mut chars, &spans);
    chars.into_iter().collect()
}

/// The words of each run as bash passes them, normalized: one string per
/// run, so words of separate commands never join. A command's own run is
/// the last of its runs; its words at the indices in `skip` (per command)
/// are left out.
fn decoded_words(cmds: &[SimpleCommand], runs: &[Vec<Run>], skip: &[Vec<usize>]) -> Vec<String> {
    cmds.iter()
        .zip(runs)
        .zip(skip)
        .flat_map(|((cmd, runs), skip)| {
            let own = runs.len().saturating_sub(1);
            runs.iter().enumerate().map(move |(k, r)| {
                let words: Vec<&str> = r
                    .source
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| {
                        k != own
                            || j.checked_sub(cmd.assignments.len())
                                .is_none_or(|w| !skip.contains(&w))
                    })
                    .map(|(_, w)| w.as_str())
                    .collect();
                normalize(&words.join(" "))
            })
        })
        .collect()
}

/// True when a program that does not read its stdin as data
/// ([`stdin_data_reader`]: `xargs`, git commands behind it, an
/// interpreter, a pager) reads a pipe, an input file or an expanding
/// heredoc: data printed anywhere in the command can become its code or
/// arguments, so nothing is exempt (item 51, fail closed).
fn non_data_reader_reads(runs: &[Vec<Run>]) -> bool {
    runs.iter().flatten().any(|r| {
        (r.feed.piped || r.feed.input || r.docs.iter().any(Option::is_none)) && !run_reads_data(r)
    })
}

/// True when redirection target `target` is a plain path to a regular
/// file: a word bash takes as written (no `$`, backtick, glob, brace,
/// tilde or blank), with no `..` part, outside `/dev` and `/proc` however
/// spelled (`//dev/stdout`, `/./proc/self/fd/1`; a relative `dev/x` too,
/// since the cwd can be `/`) (item 51, security review note 1).
fn plain_file_target(r: &shell::Redirect) -> bool {
    let t = r.target.as_str();
    let parts: Vec<&str> = t
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    r.literal
        && !t.is_empty()
        && !t.contains(|c: char| {
            c.is_whitespace() || c.is_control() || "$`*?[]{}~!\\'\"".contains(c)
        })
        && !parts.contains(&"..")
        && parts.first().is_some_and(|p| !matches!(*p, "dev" | "proc"))
}

/// Item 51, exemption 2 (the lead's direction of 2026-11-09): the body
/// of `cat > <plain path> <<'QUOTED'`, exactly: a top-level `cat` with no
/// other word, no assignment and no pipe into it, one `>` to a
/// [`plain_file_target`] and one heredoc whose delimiter is quoted. The
/// body goes to a file as written; the command runs none of it.
fn cat_file_body(chars: &[char], cmd: &SimpleCommand) -> Option<(usize, usize)> {
    let [to, doc] = cmd.redirects.as_slice() else {
        return None;
    };
    let body = doc.body_span?;
    let ok = cmd.top
        && cmd.words == ["cat"]
        && cmd.spans.len() == 1
        && cmd.assignments.is_empty()
        && !cmd.piped
        && to.op == ">"
        && plain_file_target(to)
        && doc.op == "<<"
        && doc.literal;
    // The delimiter is quoted: in the source between `cat` and the body,
    // `<<` (or `<<-`) is followed by a quote or a backslash.
    let quoted = || {
        let head: String = chars[cmd.spans[0].1..body.0.min(chars.len())]
            .iter()
            .collect();
        head.find("<<").is_some_and(|at| {
            head[at + 2..]
                .trim_start_matches('-')
                .trim_start_matches([' ', '\t'])
                .starts_with(['\'', '"', '\\'])
        })
    };
    (ok && quoted()).then_some(body)
}

/// Item 51, exemption 3 (the lead's direction of 2026-11-09): the
/// argument words of a top-level `grep`, `egrep`, `fgrep` or `rg` (no
/// wrapper, no assignment) that cannot print or run them: no option
/// before `--` reads patterns from a file (`-f`), prints only the match
/// (`-o`), replaces it (`rg -r`) or runs a program (`rg --pre`,
/// `--hostname-bin`), and its output goes to no file. `None` otherwise;
/// else the index of its first argument word.
fn grep_pattern_words(cmd: &SimpleCommand) -> Option<usize> {
    let name = cmd.words.first()?.as_str();
    if !matches!(name, "grep" | "egrep" | "fgrep" | "rg")
        || !cmd.top
        || !cmd.assignments.is_empty()
        || cmd.spans.len() != cmd.words.len()
        || cmd.redirects.iter().any(shell::Redirect::writes_file)
    {
        return None;
    }
    let shorts = if name == "rg" { "for" } else { "fo" };
    for a in cmd.words[1..].iter().take_while(|a| *a != "--") {
        let unsafe_long = [
            "--file",
            "--only-matching",
            "--replace",
            "--pre",
            "--hostname-bin",
        ]
        .iter()
        .any(|o| a.starts_with(o));
        let unsafe_short = a.len() > 1
            && a.starts_with('-')
            && !a.starts_with("--")
            && a[1..].contains(|c: char| shorts.contains(c));
        if unsafe_long || unsafe_short {
            return None;
        }
    }
    Some(1)
}

/// Item 51 (the lead's direction of 2026-11-09: the smallest set of exact
/// exemptions): the spans of the command that are data, for the substring
/// rules and for the item 31 mention of git or tollgate, and per command
/// the indices of its words among them, for the decoded-word rules: the
/// body of a [`cat_file_body`] and the words of a [`grep_pattern_words`]
/// command with no substitution in them. Nothing is data when a program
/// that does not read its stdin as data reads a pipe, an input file or an
/// expanding heredoc ([`non_data_reader_reads`]), or output can reach a
/// process substitution `>(...)` or a `coproc`, and none when the
/// command can change what `cat`, `grep` or `rg` runs: the check item 42
/// makes for git ([`git_can_change`]: a function definition, `function`,
/// `alias`, `hash`, `enable`, `source`/`.`, a PATH or `BASH*`
/// assignment, ...), and [`renames_programs`] (security review,
/// 2026-11-09). Item 42's literal messages are the other exemption
/// ([`literal_messages`]).
fn data_spans(
    command: &str,
    cmds: &[SimpleCommand],
    runs: &[Vec<Run>],
    extglob: bool,
) -> (Vec<(usize, usize)>, Vec<Vec<usize>>) {
    let mut skip = vec![Vec::new(); cmds.len()];
    let mut spans = Vec::new();
    if command.contains(">(")
        || runs
            .iter()
            .flatten()
            .any(|r| r.words.first().is_some_and(|w| w == "coproc"))
        || extglob
        || non_data_reader_reads(runs)
        || git_can_change(&without_literal_docs(command, cmds), runs)
        || runs.iter().flatten().any(renames_programs)
    {
        return (spans, skip);
    }
    let mut chars: Option<Vec<char>> = None;
    for (cmd, skip) in cmds.iter().zip(skip.iter_mut()) {
        let chars = chars.get_or_insert_with(|| command.chars().collect());
        if let Some(body) = cat_file_body(chars, cmd) {
            spans.push(body);
        } else if let Some(first_arg) = grep_pattern_words(cmd) {
            for (w, &(a, b)) in cmd.spans.iter().enumerate().skip(first_arg) {
                let raw: String = chars[a..b].iter().collect();
                if !(raw.contains('`') || raw.contains("$(") || raw.contains("<(")) {
                    spans.push((a, b));
                    skip.push(w);
                }
            }
        }
    }
    (spans, skip)
}

/// Item 51 (the lead's direction of 2026-11-09, fail closed): the raw
/// command has `@`, `!`, `+`, `*` or `?` right before `(`, which bash can
/// read as an extglob (`-@(C)`, `@(#$(...))`, also in a redirection
/// target or an assignment). `bash_ruling` passes the command without
/// its literal messages and literal top-level heredoc bodies, where bash
/// expands nothing (Rust's `assert!(`), and hands the answer on as
/// `extglob`. The lexer does not read extglobs, so no data
/// exemption applies, no program reads stdin as data, `mapfile` counts
/// as running a callback, and a mention of git or tollgate anywhere
/// denies ([`hidden_text`]).
fn extglob_like(command: &str) -> bool {
    command
        .as_bytes()
        .windows(2)
        .any(|w| matches!(w[0], b'@' | b'!' | b'+' | b'*' | b'?') && w[1] == b'(')
}

/// Sets [`Run::literal`] (item 51): the own run (the last) of a top-level
/// command whose words bash all passes as written, read from its source
/// text; never in a command with extglob-like text or `>(...)`, whose
/// commands the lexer may not see whole.
fn literal_runs(command: &str, cmds: &[SimpleCommand], runs: &mut [Vec<Run>], extglob: bool) {
    if extglob || command.contains(">(") {
        return;
    }
    let chars: Vec<char> = command.chars().collect();
    // A nested command's source text is not at hand: its words (quotes
    // removed) must hold no char that can expand, and no blank, which a
    // backtick substitution leaves (fail closed: a quoted `*` counts).
    let plain = |w: &String| !w.contains(|c: char| c.is_whitespace() || "$`*?[]{}~!()".contains(c));
    for (cmd, runs) in cmds.iter().zip(runs.iter_mut()) {
        let own = runs.len().saturating_sub(1);
        for (k, r) in runs.iter_mut().enumerate() {
            r.literal = if cmd.top && k == own {
                cmd.spans.len() == cmd.words.len()
                    && cmd.spans.iter().all(|&(a, b)| {
                        data::expands_nothing(&chars[a..b].iter().collect::<String>())
                    })
            } else {
                r.source.iter().all(plain)
            };
        }
    }
}

/// `text` with the chars of `spans` blanked ([`blank_spans`]).
fn blanked(text: &str, spans: &[(usize, usize)]) -> String {
    if spans.is_empty() {
        return text.to_owned();
    }
    let mut chars: Vec<char> = text.chars().collect();
    blank_spans(&mut chars, spans);
    chars.into_iter().collect()
}

/// R25/R26 for a Bash command.
#[must_use]
pub fn bash_ruling(ctx: &Context, command: &str) -> Ruling {
    let (cmds, ansi_c) = shell::parse_flagged(command);
    let mut runs: Vec<Vec<Run>> = cmds
        .iter()
        .map(|cmd| {
            let mut runs = Vec::new();
            expand(cmd, &[], 0, &mut runs);
            runs
        })
        .collect();
    let search = search_only(&cmds, &runs);
    let (masked, mut skip) = literal_messages(command, &cmds, &runs);
    let plain = without_literal_docs(&masked, &cmds);
    let extglob = extglob_like(&plain);
    literal_runs(command, &cmds, &mut runs, extglob);
    let (data, data_words) = data_spans(command, &cmds, &runs, extglob);
    for (s, d) in skip.iter_mut().zip(data_words) {
        s.extend(d);
    }
    if !search && let Some(deny) = text_ruling(&normalize(&blanked(&masked, &data))) {
        return deny;
    }
    let decoded_all = decoded_words(&cmds, &runs, &vec![Vec::new(); cmds.len()]);
    let runs_git = may_run_git_or_tollgate(ctx, command, &cmds, &runs, &decoded_all);
    if let Some(deny) = hidden_text(
        ctx,
        extglob,
        &data,
        runs_git,
        &plain,
        ansi_c,
        command,
        &cmds,
        &runs,
        &decoded_all,
    ) {
        return deny;
    }
    // The same rules on the words as bash passes them: quoting hides a
    // name from the text (`$'\x2d-no-verify'`, `$'\x47IT_CONFIG_COUNT'`).
    // Literal messages (item 42) and grep patterns (item 51) are left
    // out.
    let decoded = decoded_words(&cmds, &runs, &skip);
    if !search && let Some(deny) = text_ruling(&decoded.join(" ; ")) {
        return deny;
    }
    // R8, X1: a guarded variable set for the rest of the shell counts for
    // every git and tollgate in the command (best effort: order is not
    // followed).
    let shell_sets = runs.iter().flatten().find_map(shell_guarded_var);
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
                return Ruling::deny("env-loss", format!("{why} (R25)"));
            }
            if runs_git_or_tollgate(ctx, &run.words)
                && let Some((var, why)) = run
                    .assigns
                    .iter()
                    .find_map(|a| sets_guarded_var(a))
                    .or(shell_sets)
            {
                return Ruling::deny(
                    "guarded-var",
                    format!("{var} set for git or tollgate {why}"),
                );
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
        return Ruling::ask(
            "host-config-edit",
            format!("edit of the tollgate host config {} (R26)", p.display()),
        );
    }
    if let Some(dir) = ctx.protected.iter().find(|d| touches(&p, d, false)) {
        return Ruling::deny(
            "state-dir-write",
            format!("write under tollgate's dir {} (R25, R26)", dir.display()),
        );
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
        return Ruling::ask(
            "claude-settings-edit",
            format!("edit of Claude Code settings {} (R26)", p.display()),
        );
    }
    if comps.iter().any(|c| c == ".git") {
        return Ruling::ask(
            "git-dir-write",
            format!("write under .git/: {} (R26)", p.display()),
        );
    }
    if comps.iter().any(|c| c == ".githooks") {
        return Ruling::ask(
            "repo-hook-edit",
            format!("edit of a repo hook {} (R26)", p.display()),
        );
    }
    if let Some((rule, why)) = super::repo_rules(&p) {
        return Ruling::ask(rule, why);
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

    /// Item 50: `tollgate stats` groups by these ids, so they stay put.
    #[test]
    fn rule_ids_are_stable_and_hold_no_command_text() {
        let c = ctx();
        let rule = |r: Ruling| match r {
            Ruling::Deny(r) => ("deny", r.rule),
            Ruling::Ask(r) => ("ask", r.rule),
            Ruling::Allow => ("allow", ""),
        };
        for (cmd, want) in [
            ("git commit --no-verify -m x", ("deny", "no-verify")),
            ("git push --no-ver origin x", ("deny", "no-verify-abbrev")),
            ("GIT_CONFIG_COUNT=0 git commit", ("deny", "git-config-env")),
            ("env -i git commit", ("deny", "env-i")),
            ("tollgate waive --tree x", ("deny", "tollgate-waive")),
            (
                "echo x > /h/.local/state/tollgate/a",
                ("deny", "state-dir-write"),
            ),
            ("git -c core.hooksPath=/x commit", ("deny", "git-c-hooks")),
            ("git -c url.a.insteadOf=b fetch", ("ask", "git-c-url")),
            ("git send-pack o main", ("deny", "git-pack-direct")),
            ("git replace a b", ("deny", "git-replace")),
            (
                "git symbolic-ref HEAD refs/heads/x",
                ("deny", "git-symbolic-ref"),
            ),
            (
                "git update-ref refs/remotes/o/x HEAD",
                ("deny", "git-update-ref-remote"),
            ),
            ("git commit -n -m x", ("deny", "git-short-n")),
            ("git branch -M x main", ("deny", "branch-move-full")),
            ("git branch -m x y", ("ask", "branch-move")),
            ("git config core.hooksPath x", ("ask", "git-config-write")),
            ("rm .git/index.lock", ("ask", "git-lock-file")),
            ("git commit -m $'x'", ("deny", "ansi-c")),
            ("HOME=/tmp git commit -m x", ("deny", "guarded-var")),
            ("bash <<'E'\ngit status\nE", ("deny", "interpreter-stdin")),
            ("ls", ("allow", "")),
        ] {
            assert_eq!(rule(bash_ruling(&c, cmd)), want, "{cmd}");
        }
        for (file, want) in [
            (
                "/h/.config/tollgate/config.toml",
                ("ask", "host-config-edit"),
            ),
            ("/h/.local/state/tollgate/x", ("deny", "state-dir-write")),
            (
                "/w/repo/.claude/settings.json",
                ("ask", "claude-settings-edit"),
            ),
            ("/w/repo/.git/config", ("ask", "git-dir-write")),
            ("/w/repo/.githooks/pre-commit", ("ask", "repo-hook-edit")),
        ] {
            assert_eq!(rule(file_ruling(&c, file)), want, "{file}");
        }
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

    /// S1, S2: ANSI-C quoting (`$'\x2d-no-verify'`) hides a flag or a
    /// variable name from the text match; the R25 rules also see the words
    /// as bash passes them.
    #[test]
    fn ansi_c_quoted_words_deny_r25() {
        for cmd in [
            r"git commit $'\x2d-no-verify' -m x",
            r"git commit $'\055-no-verify' -m x",
            r"git commit $'\x2dn' -m x",
            r"git commit $'--no-verif' -m x",
            r"env -u $'\x47IT_CONFIG_COUNT' git commit -m x",
            r"unset $'\x47IT_CONFIG_COUNT'; git commit -m x",
            r"export $'\x47IT_CONFIG_COUNT=0'; git commit -m x",
            r"bash -c $'git commit \x2dn -m x'",
            r"git -c $'core.hooks\x50ath=/dev/null' commit -m x",
            r"e$'\x6e'v -i git commit -m x",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        // Words in separate commands do not join into a match.
        assert_eq!(bash_ruling(&ctx(), "echo env; echo -u git"), Ruling::Allow);
    }

    /// Item 31 (21c): in a command that runs git or tollgate, ANSI-C
    /// quoting, a `\c` escape and text fed to an interpreter's stdin
    /// deny; the guard does not chase bash's decoding there. Item 51: a
    /// python or perl program whose text names git denies with or without
    /// a git command next to it.
    #[test]
    fn hidden_text_in_git_commands_denies_r25() {
        for cmd in [
            r"echo $'\c\\' ; git commit -n -m x",
            r"echo $'\c\\' ; git commit $'\x2dn' -m x",
            r"git commit $'\c\\' -n -m x",
            r"git commit $'\c-\c-no-verify' -m x",
            r"git commit -m $'two\nlines'",
            r"tollgate check $'\x2d-tier' full",
            "bash <<< 'git commit -n -m x'",
            "sh <<'EOF'\ngit commit -n -m x\nEOF",
            "cat <<EOF | bash\ngit commit -n -m x\nEOF",
            "echo 'git commit -n -m x' | sh",
            "printf 'git push -n origin x' | env bash -s",
            "echo 'git push -n' |& zsh",
            "echo 'git am -n x' | (bash)",
            "bash -c \"echo 'git commit -n -m x' | sh\"",
            "sh -c 'sh <<< \"git push -n origin x\"'",
            "bash < /dev/stdin <<< 'git commit -n -m x'",
            ". /dev/stdin <<< 'git commit -n -m x'",
            "git status; python3 - <<'EOF'\nimport os; os.system('git commit -n -m x')\nEOF",
            "git status; python3 <<< 'import os; os.system(\"git commit -n\")'",
            "git status; perl <<< 'system(\"git commit -n -m x\")'",
            "python3 - <<'EOF'\nimport os; os.system('git commit -n -m x')\nEOF",
            "python3 <<< 'import os; os.system(\"git commit -n\")'",
            "perl <<< 'system(\"git commit -n -m x\")'",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "git commit -F - <<'EOF'\nsubject\n\nbody\nEOF",
            "git commit -m \"$(cat <<'EOF'\nsubject\nEOF\n)\"",
            "cat <<'EOF' > notes.md\ngit is nice\nEOF",
            "git show HEAD:a.json | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
            "git log --format=%s | perl -ne 'print if /fix/'",
            "git diff | wc -l",
            "git status || echo no",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    /// A harmless command is not a git command because of a substring: a
    /// name inside a longer word or a directory part is not a program.
    #[test]
    fn names_inside_other_words_do_not_count_as_git() {
        for cmd in [
            "python3 - <<'EOF'\nprint('https://github.com/x/y and a digit')\nEOF",
            "python3 - <<'EOF'\nopen('.gitignore').read()\nEOF",
            "python3 - <<'EOF'\nopen('tollgate.toml').read()\nEOF",
            "python3 - <<'EOF'\nopen('/h/.local/state/tollgate/flaky.jsonl').read()\nEOF",
            "cd /h/Repos/tollgate; python3 - <<'EOF'\nprint(1)\nEOF",
            "cd /h/Repos/tollgate && python3 -I - a <<'EOF'\nprint(1)\nEOF",
            "cd /h/Repos/tollgate-core2; python3 - <<'EOF'\nprint(1)\nEOF",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        // A real name still counts, however it is written.
        for cmd in [
            "python3 - <<'EOF'\nimport os; os.system('git commit -m x')\nEOF",
            "python3 - <<'EOF'\nimport os; os.system('/usr/bin/git commit -m x')\nEOF",
            "python3 - <<'EOF'\nimport os; os.system('tollgate check')\nEOF",
            "python3 - <<'EOF'\nimport os; os.system('g\"i\"t status')\nEOF",
            "cd /h/git; python3 - <<'EOF'\nimport os; os.system('git push')\nEOF",
            "/usr/bin/git status; python3 - <<'EOF'\nprint(1)\nEOF",
            "g\"i\"t status; python3 - <<'EOF'\nprint(1)\nEOF",
            "cd /h/Repos/tollgate; git status; python3 - <<'EOF'\nimport subprocess\nEOF",
            "cd git; git status; python3 - <<'EOF'\nimport subprocess\nEOF",
            "cd /h/Repos/tollgate; echo 'git commit -m x' | sh",
            // A `cd` target never removes part of another word.
            "printf 'git commit -n' | sh; cd g",
            "printf 'git commit -n' | sh; cd i",
            "abcd git commit | sh; cd g",
            "printf 'git commit -n' | sh; cd git",
            // A target that is not spelled out does not account for a name.
            "cd g\\\nit; printf 'git commit -n' | sh",
            "cd 'git'; printf 'git commit -n' | sh",
            r"cd $'\x67it'; printf 'git commit -n' | sh",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// `$'` is ANSI-C quoting only where bash reads it so: not at the end
    /// of a single-quoted regex, in double quotes or in a heredoc body.
    #[test]
    fn dollar_quote_as_data_is_not_ansi_c_r25() {
        for cmd in [
            "git status --porcelain | grep -v '^?? x$'",
            "grep -c 'digit$' README.md; git status",
            "git log --format=%s | grep -E 'fix$'",
            "git commit -F - <<'EOF'\nthe $'x' form\nEOF",
            "git log --grep=\"a$'b\"",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        for cmd in [
            r"git commit -m $'two\nlines'",
            r#"git commit -m "$(echo $'x')""#,
            r"git commit -m `echo $'x'`",
            r"x=$'a'; git status",
            r"git status; echo a$'b'",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// Text rules guard against running or setting a name. A command that
    /// only reads and searches passes it as data, so it can look for it.
    #[test]
    fn searching_for_a_guarded_name_is_allowed_r25() {
        for cmd in [
            "grep -rn 'GIT_CONFIG_KEY_0' src | head -5",
            "grep -n -- '--no-verify' notes.md",
            "rg 'env -i' docs",
            "grep -c 'tollgate waive' docs/spec.md | wc -l",
            "cat a.md | grep GIT_CONFIG_COUNT",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        for cmd in [
            "grep x a; git commit --no-verify -m x",
            "grep -- --no-verify a | sh",
            "grep \"$(git commit --no-verify -m x)\" a",
            "GIT_CONFIG_COUNT=0 grep x a",
            "env -i grep x a",
            "rg --pre ./f GIT_CONFIG_COUNT a",
            "cat <<'EOF' > run.sh\ngit commit --no-verify\nEOF",
            "cat <<'EOF' | sh\ngit commit --no-verify\nEOF",
            "grep -- --no-verify a > run.sh",
            "export GIT_CONFIG_COUNT=0",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// The ANSI-C decoder reads `$'...'` as bash does (`\c\\` is one
    /// character), so the words it hides are checked (R25): a decoded
    /// `git` is a command word that runs git (item 51).
    #[test]
    fn decoded_words_without_a_git_mention_deny_r25() {
        for cmd in [
            r"echo $'\c\\' ; $'\x67it' commit -n -m x",
            r"$'\x67it' commit $'\c\\' -n -m x",
            r"$'\x67it' commit $'\c\\\\' $'\x2dn' -m x",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        assert_eq!(bash_ruling(&ctx(), r"printf %s $'\c\\x'"), Ruling::Allow);
    }

    /// Variables that choose the program git reaches a server with
    /// (`GIT_SSH*`, `GIT_PROXY_COMMAND`) or the dir git and the hooks run
    /// git's programs from (`GIT_EXEC_PATH`) are denied for git and
    /// tollgate (R25, X1).
    #[test]
    fn transport_variables_in_front_of_git_deny_r25() {
        for cmd in [
            "GIT_SSH_COMMAND=/tmp/f git commit -m x",
            "GIT_SSH=/tmp/f git commit -m x",
            "GIT_SSH_VARIANT=simple git push origin feat",
            "GIT_PROXY_COMMAND=/tmp/p git fetch origin",
            "GIT_EXEC_PATH=/tmp/x git commit -m x",
            "env GIT_SSH_COMMAND=/tmp/f git commit -m x",
            "export GIT_SSH_COMMAND=/tmp/f; git commit -m x",
            "GIT_SSH_COMMAND=/tmp/f; git commit -m x",
            "declare -x GIT_EXEC_PATH=/tmp/x && git push",
            "GIT_SSH_COMMAND=/tmp/f tollgate check",
            "bash -c 'GIT_SSH=/tmp/f git push origin feat'",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "GIT_SSH_COMMAND=/tmp/f cargo test",
            "echo $GIT_SSH_COMMAND",
            "git config --get core.sshCommand",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
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
            "git config url./tmp/fake.git.insteadOf git@gitlab.example:v/r.git",
            "git config --global url.x.pushInsteadOf y",
            "git config set url.x.insteadOf y",
            "git -c url./tmp/f.git.insteadOf=git@h:r.git fetch origin",
            "git --config-env=url.x.insteadOf=V fetch",
            "git config --global core.sshCommand /tmp/f",
            "git config set --global core.sshcommand /tmp/f",
            "git config core.gitProxy /tmp/p",
            "git config ssh.variant simple",
            "git config --remove-section ssh",
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

    /// Item 42: a commit, merge or tag message is data git stores. A
    /// literal message value (`-m`, `--message`, a quoted heredoc on
    /// `-F -`, the `"$(cat <<'EOF' ... EOF)"` form) is not scanned by the
    /// text rules, so a message can name a flag or a variable.
    #[test]
    fn literal_messages_are_data_item42() {
        for cmd in [
            "git commit -m \"docs: mention --no-verify in README\"",
            "git commit -m 'Fix env' -i src/a.rs",
            "git commit -m 'GIT_CONFIG_COUNT and core.hooksPath in docs'",
            "git commit -am 'explain env -i'",
            "git commit -m'--no-verify' a.rs",
            "git commit --message='skip --no-v in tests'",
            "git commit --message 'x --no-verify'",
            "git commit -m subject -m 'body: unset GIT_CONFIG_KEY_0'",
            "git commit -m 'it'\"'\"'s --no-verify'",
            "git commit -m 'path C:\\code'",
            "/usr/bin/git commit -m 'mention --no-verify'",
            "git -C /w/repo commit -q -m 'tollgate waive is not for agents'",
            "cd /w/repo && git add a.md && git commit -m 'docs: --no-verify'",
            "git commit -m \"$(cat <<'EOF'\nGuard: deny --no-verify\n\nGIT_CONFIG_COUNT (item 42)\nEOF\n)\"",
            "git commit -m \"$(cat <<\"EOF\"\nenv -i drops it)\nEOF\n)\" a.rs",
            "git commit -F - <<'EOF'\nsubject --no-verify\n\nenv -i and GIT_CONFIG_COUNT\nEOF",
            "git commit --file=- <<'MSG'\ntollgate waive\nMSG",
            "git commit -F - <<EOF\nplain --no-verify\nEOF",
            "git tag -a v1 -m 'no --no-verify here'",
            "git merge --no-ff -m 'merge: env -i fix' feat",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        for cmd in [
            // The flag outside the message, or a word git reads as a flag.
            "git commit -m x --no-verify",
            "git commit -m 'x' --no-verify",
            "git commit -um --no-verify",
            "git commit -F -m --no-verify",
            "git commit -C -m --no-verify",
            "git commit --author -m --no-verify",
            "git commit --mess '--no-verify'",
            "git commit -- -m --no-verify",
            "git commit -m x 'b --no-verify'",
            "git commit -m 'a' -m 'b' -n",
            "git commit -m {x,--no-verify}",
            "git commit -m --no-verif?",
            "git commit -nm 'mention'",
            // Text that is not a literal: variables, substitutions,
            // ANSI-C.
            "git commit -m \"$X --no-verify\"",
            "git commit -m \"$(echo --no-verify)\"",
            "git commit -m \"`echo --no-verify`\"",
            "git commit -m $'x\\n--no-verify'",
            "git commit -m \"$(cat <<EOF\n$(env -i git commit)\nEOF\n)\"",
            "git commit -m \"$(cat <<'EOF'\nx\nEOF\necho --no-verify)\"",
            "git commit -m \"$(cat <<'EOF'\nx\nEOF\n)\" ; git commit --no-verify -m y",
            "git commit -F - <<EOF\n$(echo --no-verify)\nEOF",
            "git commit -F - <<EOF\n`git commit -n -m x`\nEOF",
            "git commit -F msg.txt <<'EOF'\n--no-verify\nEOF",
            // A message of another command, a nested shell, a subshell.
            "echo git commit -m '--no-verify' | sh",
            "bash -c \"git commit -m '--no-verify'\"",
            "eval git commit -m \"'--no-verify'\"",
            "(git commit -m 'a' --no-verify)",
            // (`cat > m.txt <<'EOF'` with the flag is item 51's exemption 2.)
            "cat <<'EOF' | sh\ngit commit -m '--no-verify'\nEOF",
            // Variables, aliases, -c and env stay checked.
            "GIT_CONFIG_COUNT=1 git commit -m 'x'",
            "git -c core.hooksPath=/x commit -m 'core.hooksPath'",
            "env -i git commit -m 'x'",
            "alias g='git commit --no-verify'; g -m 'x'",
            "git commit -m 'x'; export GIT_CONFIG_COUNT=0",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// Item 42 follow-up: with `-e`/`--edit` git runs the editor on a file
    /// that holds the message, so the message is no longer only data
    /// (`GIT_EDITOR=bash git tag -a -e -m '<script>' t1` runs the script).
    /// A message is masked only when git cannot start an editor on it:
    /// no edit option (also in a cluster or abbreviated), no option the
    /// table does not know, and no editor set by the same Bash command.
    #[test]
    fn literal_messages_stay_checked_when_an_editor_can_run() {
        for cmd in [
            "GIT_EDITOR=bash git tag -a -e -m 'git push --no-verify origin HEAD' t1",
            "export GIT_EDITOR=bash; git tag -a -em 'git push --no-verify origin HEAD' t1",
            "env GIT_EDITOR=bash git commit --allow-empty --edit --message='GIT_CONFIG_COUNT=0 git push origin HEAD'",
            "GIT_EDITOR=bash git merge -e -m 'git push --no-verify origin HEAD' feature",
            "GIT_EDITOR=bash git tag -a -e t1 -F - <<'EOF'\ngit push --no-verify origin HEAD\nEOF",
            // The editor from config or the inherited environment.
            "git tag -a -e -m 'git push --no-verify origin HEAD' t1",
            "git commit --allow-empty -m 'git push --no-verify' -e",
            "git commit --allow-empty -m 'git push --no-verify' -ve",
            "git tag -m 'git push --no-verify' -ase t1",
            "git merge -m 'git push --no-verify' --edit feat",
            "git commit -m 'git push --no-verify' --no-edit --edit",
            "git commit -F - --edit <<'EOF'\ngit push --no-verify\nEOF",
            // git takes an abbreviation: `--edi` is `--edit`.
            "git tag -a -m 'git push --no-verify' --edi t1",
            "git commit -m 'git push --no-verify' --ed",
            // An option the table does not know can be one that edits.
            "git commit -m 'git push --no-verify' --bogus",
            "git commit -m 'git push --no-verify' -Z",
            // An editor set by the same command, without an edit option.
            "GIT_EDITOR=bash git commit -m 'git push --no-verify'",
            "VISUAL=sh git tag -a -m 'git push --no-verify' t1",
            "EDITOR=sh git merge -m 'git push --no-verify' feat",
            "GIT_SEQUENCE_EDITOR=sh git commit -m 'git push --no-verify'",
            "env EDITOR=sh git commit -m 'git push --no-verify'",
            "export VISUAL=sh && git commit -m 'git push --no-verify'",
            "declare -x GIT_EDITOR=sh; git commit -m 'git push --no-verify'",
            "GIT_EDITOR=sh; git commit -m 'git push --no-verify'",
            "git -c core.editor=sh tag -a -m 'git push --no-verify' t1",
            "git -c Core.Editor=sh commit -m 'git push --no-verify'",
            "git -c sequence.editor=sh commit -m 'git push --no-verify'",
            "git --config-env=core.editor=E commit -m 'git push --no-verify'",
            "git -C /w/repo -c core.editor=sh commit -m 'git push --no-verify'",
            "env -S 'GIT_EDITOR=bash' git commit -m 'git push --no-verify'",
            // A quoted edit option is still one.
            "git tag -a \"-e\" -m 'git push --no-verify' t1",
            "git tag -a '--edit' -m 'git push --no-verify' t1",
            // A word that expands can become the edit option.
            "E=-e; git tag -a $E -m 'git push --no-verify' t1",
            "git tag -a \"$E\" -m 'git push --no-verify' t1",
            "git tag -a -m 'git push --no-verify' t1 $(printf -- -e)",
            "git tag -a -m 'git push --no-verify' t1 *",
            "git tag -a -m 'git push --no-verify' t1 {-e,x}",
            "git tag -a -m 'git push --no-verify' t1 ~",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "git commit -m 'docs: mention --no-verify'",
            "git commit --no-edit -m 'docs: mention --no-verify'",
            "git merge --no-edit -m 'merge: --no-verify docs' feat",
            "git tag -a v1 -m 'no --no-verify here'",
            "git commit -e -m 'plain message'",
            "GIT_EDITOR=true git commit -m 'plain message'",
            "GIT_EDITOR=true git rebase --continue",
            "git commit -m 'docs: GIT_EDITOR and core.editor'",
            "git commit -m 'docs: --no-verify' -- 'a b.md' c\\ d.md",
            "cd /w/repo;git commit -m 'docs: --no-verify' a.md",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    /// Item 42 recheck: a masked message is data only while the `git` that
    /// gets it is the real git. A function, an alias, the hash table, a
    /// loaded builtin, a sourced file, a trap or a changed PATH can turn
    /// the message into code (`git() { eval "$3"; }; git commit -m
    /// '<script>'`), and a wrapper can add `-e`. Nothing is masked in a
    /// Bash command that can change what `git` runs, or when the command
    /// word is not bare `git` or a system path to it.
    #[test]
    fn literal_messages_stay_checked_when_git_can_be_redefined() {
        let mut allowed = Vec::new();
        let p = "git push --no-verify origin HEAD";
        for cmd in [
            // Functions.
            format!("git() {{ eval \"$3\"; }}; git commit -m '{p}'"),
            "git() { bash -c \"$3\"; }; git commit -m 'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.hooksPath GIT_CONFIG_VALUE_0=/dev/null git push'".to_owned(),
            "git() { eval \"$3\"; }; git commit -m 'tollgate waive --tree x'".to_owned(),
            format!("git () {{ eval \"$3\"; }}\ngit commit -m '{p}'"),
            format!("git()(eval \"$3\"); git commit -m '{p}'"),
            format!("function git {{ eval \"$3\"; }}; git commit -m '{p}'"),
            format!("function git() {{ eval \"$3\"; }}\ngit commit -m '{p}'"),
            format!("'git'() {{ eval \"$3\"; }}; git commit -m '{p}'"),
            format!("unset GIT_EDITOR; git() {{ command git -c core.editor=bash \"$@\" -e; }}; git tag -a -m '{p}' t1"),
            // Aliases.
            format!("shopt -s expand_aliases\nalias git='eval'\ngit commit -m '{p}'"),
            format!("shopt -s expand_aliases\nalias git='GIT_EDITOR=bash git '; alias tag='tag -e '\ngit tag -a -m '{p}' t1"),
            format!("alias git=eval\ngit commit -m '{p}'"),
            format!("shopt -s expand_aliases; BASH_ALIASES[git]=eval\ngit commit -m '{p}'"),
            // The hash table, loaded builtins, sourced files, traps.
            format!("hash -p /tmp/x/run git; git commit -m '{p}'"),
            format!("BASH_CMDS[git]=/tmp/x/run; git commit -m '{p}'"),
            format!("enable -f /tmp/x/git.so git; git commit -m '{p}'"),
            format!("source /tmp/x/fn.sh; git commit -m '{p}'"),
            format!(". ./fn.sh && git commit -m '{p}'"),
            format!("trap 'eval \"${{BASH_COMMAND#*-m }}\"' DEBUG; git commit -m '{p}'"),
            format!("eval x; git commit -m '{p}'"),
            // PATH.
            format!("PATH=/tmp/x:$PATH git commit -m '{p}'"),
            format!("PATH=/tmp/x:$PATH; git commit -m '{p}'"),
            format!("export PATH=/tmp/x:$PATH; git commit -m '{p}'"),
            format!("env PATH=/tmp/x git commit -m '{p}'"),
            format!("read -r PATH <<< /tmp/x; git commit -m '{p}'"),
            format!("printf -v PATH /tmp/x; git commit -m '{p}'"),
            format!("mapfile -t PATH <<< /tmp/x; git commit -m '{p}'"),
            format!("T=TH; export \"PA$T=/tmp/x\"; git commit -m '{p}'"),
            format!("declare -n P=PATH; P=/tmp/x; git commit -m '{p}'"),
            format!("X=PATH=1; : $((X)); git commit -m '{p}'"),
            format!("((PATH=1)); git commit -m '{p}'"),
            format!("let PATH=1; git commit -m '{p}'"),
            format!(": ${{PATH:=/tmp/x}}; git commit -m '{p}'"),
            format!("[[ X -eq 1 ]]; git commit -m '{p}'"),
            format!("for PATH in /tmp/x; do git commit -m '{p}'; done"),
            format!("select PATH in /tmp/x; do git commit -m '{p}'; done"),
            format!("coproc PATH {{ :; }}; git commit -m '{p}'"),
            // An editor set without `=`, or one from config let back in.
            format!("printf -v GIT_EDITOR bash; export GIT_EDITOR; git commit -m '{p}'"),
            format!("read GIT_EDITOR <<< bash; git commit -m '{p}'"),
            format!("unset GIT_EDITOR; git commit -m '{p}'"),
            format!("declare -n E=GIT_EDITOR; E=bash; git commit -m '{p}'"),
            // A command word that is not the real git, or a wrapper that
            // adds words or changes the lookup.
            format!("./git commit -m '{p}'"),
            format!("../x/git commit -m '{p}'"),
            format!("/tmp/x/git commit -m '{p}'"),
            format!("x/git commit -m '{p}'"),
            format!("git-commit -m '{p}'"),
            format!("printf -- '-e\\n' | xargs git tag -a -m '{p}' t1"),
            format!("env -S 'git' commit -m '{p}'"),
            format!("sudo git commit -m '{p}'"),
            format!("exec git commit -m '{p}'"),
        ] {
            if !deny(&cmd) {
                allowed.push(cmd);
            }
        }
        assert!(allowed.is_empty(), "allowed: {allowed:#?}");
        for cmd in [
            "git commit -m 'docs: mention --no-verify'",
            "/usr/bin/git commit -m 'docs: mention --no-verify'",
            "/bin/git commit -m 'docs: mention --no-verify'",
            "command git commit -m 'docs: mention --no-verify'",
            "timeout 600 git commit -m 'docs: mention --no-verify'",
            "cd /w/repo && git add a.md && git commit -m 'docs: --no-verify'",
            "tollgate wait j1 && git commit -m 'docs: --no-verify'",
            "cargo fmt && git add -A && git commit -m \"$(cat <<'EOF'\nGuard: GIT_CONFIG_COUNT, alias, hash, PATH=x, git() { eval; }\nEOF\n)\"",
            "git commit -m 'docs: alias git=eval, hash -p, export PATH, unset GIT_EDITOR'",
            "if git diff --quiet; then git commit -m 'docs: --no-verify'; fi",
            "RUST_LOG=debug cargo test && git commit -m 'docs: --no-verify'",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    /// Item 51 (security review notes 2 and 3, and the lead's correction of
    /// 2026-11-09: there is no OS sandbox, so the guard is the only
    /// layer). Whether a command runs git or tollgate is read from its
    /// parsed command words; data (a `cat` heredoc, a `grep` pattern) does
    /// not make it run git. An interpreter's program is code, not data:
    /// it can start git itself, so one whose program text names git or
    /// tollgate (a heredoc, a here-string, `-c`/`-e`, the assignments it
    /// sees, or a pipe it reads its program from) denies whatever the
    /// command's own words run. There is no allow-list of safe programs.
    #[test]
    fn interpreter_text_is_code_item51() {
        for cmd in [
            // Programs whose text names no git, tollgate, flag or variable.
            "python3 - <<'PY'\np='notes.md'; s=open(p).read()\ns=s.replace('a', 'b')\nopen(p,'w').write(s)\nPY\ncp notes.md b.md && grep -n x b.md",
            "python3 -c 'import json; print(json.dumps({\"a\": 1}))'",
            "git show HEAD:a.json | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
            "git log --format=%s | perl -ne 'print if /fix/'",
            "node -e 'console.log(1)' && cargo test",
            "python3 scripts/stats.py --repo acme",
            "cd /h/Repos/tollgate && python3 -I - a <<'EOF'\nprint(1)\nEOF",
            // Data that names git does not run git.
            "cat > notes.md <<'EOF'\ngit commit, then tollgate status\nEOF\npython3 - <<'EOF'\nprint(1)\nEOF",
            // Exemption 4: a clean heredoc program in a command whose
            // words run no git, next to a mention of git or tollgate.
            "grep -n git a.md; python3 - <<'EOF'\nprint(1)\nEOF",
            "echo tollgate; python3 - <<'EOF'\nprint(1)\nEOF",
            "echo git; perl - <<'EOF'\nprint 1;\nEOF",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        for cmd in [
            // A program that starts git with a hook-skip flag, in a command
            // with no git word.
            "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'commit', '-n', '-m', 'x'])\nEOF",
            "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['git', 'commit', '--no-verify', '-m', 'x'])\nEOF",
            "perl - <<'EOF'\nsystem('git', 'commit', '-n', '-m', 'x');\nEOF",
            "bash -s <<'EOF'\ngit commit -n -m x\nEOF",
            "bash -s <<'EOF'\ngit commit --no-verify -m x\nEOF",
            "python3 <<< 'import os; os.system(\"git push -n\")'",
            "python3 -c 'import subprocess; subprocess.run([\"git\", \"commit\", \"-n\"])'",
            "perl -e 'system(\"git commit -n -m x\")'",
            "ruby -e 'system(\"git commit -n -m x\")'",
            "node -e 'require(\"child_process\").execSync(\"git commit -n -m x\")'",
            "deno eval 'new Deno.Command(\"git\", {args: [\"commit\", \"-n\"]}).outputSync()'",
            "php -r 'system(\"git commit -n -m x\");'",
            "lua -e 'os.execute(\"git commit -n -m x\")'",
            "Rscript -e 'system(\"git commit -n -m x\")'",
            "python3 - <<'EOF'\nimport os; os.system('tollgate waive --tree x')\nEOF",
            // The name built from what the program sees.
            "G=git python3 - <<'EOF'\nimport os; os.system(os.environ['G'] + ' commit -n')\nEOF",
            "export G=git; python3 - <<'EOF'\nimport os; os.system(os.environ['G'] + ' commit -n')\nEOF",
            // Program text the guard cannot see: the whole command counts.
            "printf 'import os; os.system(\"git commit -n\")' | python3",
            "echo 'print(\"git\")' | python3 -",
            "python3 - <<EOF\nprint(\"$X git\")\nEOF",
            "python3 x.py <<'EOF'\ngit commit -n\nEOF",
            "sh <<'EOF'\necho git\nEOF",
            // The 2026-11-09 commands that only named git or tollgate in
            // python strings now deny again: no OS sandbox stands behind
            // the guard (agents use a script file).
            "cd /w/repo && python3 -I - a.md <<'PY'\nimport sys\np = sys.argv[1]; s = open(p).read()\ns = s.replace('git commit -n', 'tollgate wait x && git commit')\nopen(p, 'w').write(s)\nPY\ncp a.md b.md && grep -n 'tollgate' b.md",
            "cd /w/repo && python3 -I - a.jsonl <<'PY'\nimport json, sys\nfor l in open(sys.argv[1]):\n    x = json.loads(l)\n    if 'env -i' in x['err'] or 'GIT_CONFIG_COUNT' in x['err']:\n        print(x['cmd'])\nPY",
            // Not exemption 4: a here-string, a pipe, or text that names a
            // guarded flag or variable, next to a mention of git.
            "echo git; python3 <<< 'print(1)'",
            "echo git; printf 'print(1)' | python3",
            "echo git; python3 - <<'EOF'\nprint('env -i')\nEOF",
            "echo git; python3 - <<'EOF'\nprint('GIT_CONFIG_COUNT')\nEOF",
            // An interpreter that reads text from stdin next to git or
            // tollgate (item 31), whatever the text.
            "python3 - <<'EOF'\nprint(1)\nEOF\ngit commit -m x",
            "python3 - <<'EOF'\nprint(1)\nEOF\n/usr/bin/git status",
            "tollgate status; python3 - <<'EOF'\nprint(1)\nEOF",
            "python3 - <<'EOF' && git diff --stat\nprint(1)\nEOF",
            "git status && python3 <<< 'print(1)'",
            "git status && perl - <<'EOF'\nprint 1;\nEOF",
            "git status && ruby <<'EOF'\nputs 1\nEOF",
            "printf 'print(1)' | python3; git status",
            "python3 < x.py; git status",
            "python3 x.py <<'EOF'\ndata\nEOF\ngit status",
            // git where the words run it: a substitution, a subshell, a
            // nested shell, eval, a function body, an alias value, find
            // -exec, a wrapper, a shell's heredoc.
            "echo $(git rev-parse HEAD); python3 - <<'EOF'\nprint(1)\nEOF",
            "echo `git rev-parse HEAD`; python3 - <<'EOF'\nprint(1)\nEOF",
            "(git status); python3 - <<'EOF'\nprint(1)\nEOF",
            "bash -c 'git status'; python3 - <<'EOF'\nprint(1)\nEOF",
            "eval git status; python3 - <<'EOF'\nprint(1)\nEOF",
            "f() { git status; }; python3 - <<'EOF'\nprint(1)\nEOF\nf",
            "function f { git status; }; python3 - <<'EOF'\nprint(1)\nEOF\nf",
            "alias g='git status'; python3 - <<'EOF'\nprint(1)\nEOF\ng",
            "find . -name x -exec git add {} +; python3 - <<'EOF'\nprint(1)\nEOF",
            "find . -exec sh -c 'git add \"$1\"' _ {} \\;; python3 - <<'EOF'\nprint(1)\nEOF",
            "echo a | xargs git add; python3 - <<'EOF'\nprint(1)\nEOF",
            "sudo -u x env git status; python3 - <<'EOF'\nprint(1)\nEOF",
            "eval \"python3 - <<'EOF'\nprint(1)\nEOF\ngit status\"",
            "(python3 - <<'EOF'\nprint(1)\nEOF\ngit status)",
            // A command word the guard cannot read may be git.
            "G=x; $G status; python3 - <<'EOF'\nprint(1)\nEOF",
            "/usr/bin/gi? status; python3 - <<'EOF'\nprint(1)\nEOF",
            "/usr/bin/g{i,}t status; python3 - <<'EOF'\nprint(1)\nEOF",
            "hash -p /usr/bin/x g; g status; python3 - <<'EOF'\nprint(1)\nEOF",
            "BASH_ALIASES[g]=x; g status; python3 - <<'EOF'\nprint(1)\nEOF",
            "enable -f ./x.so g; g status; python3 - <<'EOF'\nprint(1)\nEOF",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// Item 51, security review of 9efeca2: an interpreter's options are
    /// not parsed for its program text. Every argument word is program
    /// text (fail closed: a value of an option the guard does not know, a
    /// `perl -M` module line, `php -R`), and a program that reads text
    /// (a heredoc, a here-string, a pipe) is code unless it is a known
    /// data reader, so an interpreter missing from the list is still
    /// checked. Data readers with the same text pass.
    #[test]
    fn interpreter_options_and_registry_fail_closed_item51() {
        for cmd in [
            // Values and code options the old option table missed.
            "perl \"-Mstrict; system(q(git commit -n -m x))\" -e 1",
            "perl -I 'lib; system(q(git commit -n))' -e 1",
            "php -R 'system(\"git commit -n -m x\");'",
            "php -B 'system(\"git commit -n -m x\");' -r 1",
            "python3 --check-hash-based-pycs never -c 'import os; os.system(\"git commit -n\")'",
            "node --input-type module -e 'require(\"child_process\").execSync(\"git commit -n\")'",
            "deno eval 'eval(Deno.args[0])' 'new Deno.Command(\"git\", {args: [\"commit\", \"-n\"]}).outputSync()'",
            // Interpreters the old list did not know.
            "pypy3 -c \"import os; os.system('git commit -n -m x')\"",
            "pypy3 - <<'EOF'\nimport os; os.system('git commit -n -m x')\nEOF",
            "gawk 'BEGIN { system(\"git commit -n -m x\") }'",
            "awk 'BEGIN { system(\"git commit -n -m x\") }' /dev/null",
            "busybox awk 'BEGIN { system(\"git commit -n -m x\") }'",
            "tclsh <<'EOF'\nexec git commit -n -m x\nEOF",
            "pwsh -c 'git commit -n -m x'",
            "osascript -e 'do shell script \"git commit -n -m x\"'",
            "sqlite3 a.db '.shell git commit -n -m x'",
            // A program the guard does not know, reading text.
            "guile <<'EOF'\n(system \"git commit -n -m x\")\nEOF",
            "ssh localhost <<'EOF'\ngit commit -n -m x\nEOF",
            "printf '!git commit -n -m x\\n' | ed notes.txt",
            "echo 'git commit -n -m x' | some-runner",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "cat > notes.tcl <<'EOF'\nexec git commit -n -m x\nEOF",
            "grep -n 'system(\"git commit -n -m x\")' notes.awk",
            "jq -r '.cmd' <<'EOF'\n{\"cmd\": \"git commit -n -m x\"}\nEOF",
            "git status | sed -n 1p",
            "git log --oneline | awk '{print $1}'",
            "cargo test 2>&1 | tail -3",
            "bash scripts/ci.sh tollgate-core2",
            "python3 scripts/stats.py --repo acme",
            "cat > f.md <<'EOF'\nnever push -f\nEOF\ngit diff | less",
            "git diff | some-pager",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
    }

    /// Item 51 (the lead's direction of 2026-11-09: the smallest set of
    /// exact exemptions). Besides item 42's literal messages, only two
    /// kinds of text are data to the substring rules and to the item 31
    /// mention of git: the body of `cat > <plain path> <<'QUOTED'`, and
    /// the arguments of a `grep`/`rg` that cannot print or run them, in a
    /// command where no program that reads a pipe or a file is anything
    /// but a data reader. Everything else is checked as before item 51.
    #[test]
    fn exact_data_exemptions_item51() {
        for cmd in [
            // `cat > <plain path> <<'QUOTED'`.
            "cat > /tmp/s/msg.txt <<'EOF'\nnever use --no-verify, env -i or GIT_CONFIG_COUNT=0\nEOF\ngit commit -F /tmp/s/msg.txt",
            "cd /w/repo && cat > tests/x.rs <<'RS'\n    \"git commit --no-verify -m x\",\nRS\ncargo test",
            "cat > m.txt <<'EOF'\n--no-verify\nEOF",
            "cat > notes.md <<'EOF'\nrun git commit\nEOF\necho $'x'",
            // grep and rg patterns.
            "grep -c 'GIT_CONFIG_KEY_0' src/guard/rules.rs; git status -sb",
            "grep -n 'gitlab\\|--no-verify' notes.md; tollgate report j",
            "cd /w/repo && grep -rn -i 'tollgate_test_install' src | head; git log -1",
            "rg -n -- 'env -i|GIT_CONFIG_COUNT' docs; git status",
            "grep -c 'GIT_CONFIG_KEY_0' src/a.rs; tollgate config --effective | tail -2",
            "jq -r .x <<'EOF'\n{\"x\": \"git commit -n\"}\nEOF",
            "mapfile -t lines <<'EOF'\ngit commit -n -m x\nEOF",
            "head -n 2 <<'EOF'\ngit commit -n -m x\nEOF",
            "cut -d: -f1 <<'EOF'\ngit:commit\nEOF",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
        for cmd in [
            // Not exactly `cat > <plain path> <<'QUOTED'`.
            "cat >> notes.md <<'EOF'\n--no-verify\nEOF",
            "cat > $F <<'EOF'\n--no-verify\nEOF",
            "cat > ~/notes.md <<'EOF'\n--no-verify\nEOF",
            "cat > notes.md <<EOF\n--no-verify\nEOF",
            "cat -v > notes.md <<'EOF'\n--no-verify\nEOF",
            "cat <<'EOF' > run.sh\ngit commit --no-verify\nEOF",
            "env cat > notes.md <<'EOF'\n--no-verify\nEOF",
            "X=1 cat > notes.md <<'EOF'\n--no-verify\nEOF",
            "tee notes.md <<'EOF' >/dev/null\ntollgate waive\nEOF",
            "jq -r .x <<'EOF'\n{\"x\": \"git commit --no-verify\"}\nEOF",
            // Security review note 1: a "file" that is the pipe again.
            "cat > /dev/stdout <<'EOF' | sh\ngit commit --no-verify\nEOF",
            "cat > /proc/self/fd/1 <<'EOF'\ngit commit --no-verify\nEOF",
            "cat > //dev/stdout <<'EOF'\n--no-verify\nEOF",
            "cat > /dev/./stdout <<'EOF'\n--no-verify\nEOF",
            "cat > /./proc/123/fd/1 <<'EOF'\n--no-verify\nEOF",
            "cat > a/../dev/stdout <<'EOF'\n--no-verify\nEOF",
            "cat > dev/stdout <<'EOF'\n--no-verify\nEOF",
            // A data body next to a program that reads a pipe.
            "cat > f.txt <<'EOF'\n--no-verify\nEOF\ngit diff | less",
            "cat > f.txt <<'EOF'\n--no-verify\nEOF\ncat f.txt | xargs git commit -m x",
            "cat > f.txt <<'EOF' > >(sh)\n--no-verify\nEOF",
            // Security review note 2: a program that repeats its words into
            // a pipe or a file, or reads them from one.
            "grep -o -- --no-verify notes.md | some-runner",
            "rg --pre ./x -- --no-verify notes.md",
            "grep -- --no-verify notes.md > run.sh",
            "grep -- --no-verify notes.md | sed 's/x/y/e'",
            "jq -rn '\"git commit --no-verify\"' | some-runner",
            "jq -rn '\"git commit -n\"' | some-runner",
            "echo --no-verify",
            "echo 'git commit -n -m x' | some-runner",
            // Security review note 3: a reader with an option that runs a
            // program is no data reader.
            "sort --compress-program=sh <<'EOF'\ngit commit -n -m x\nEOF",
            "sort --compress-prog=sh <<'EOF'\ngit commit -n -m x\nEOF",
            "cat --show-all <<'EOF'\ngit commit -n -m x\nEOF",
            "grep --pre=sh x <<'EOF'\ngit commit -n -m x\nEOF",
            "tee >(sh) <<'EOF'\ngit commit -n -m x\nEOF",
            // Review note on stdin_data_reader: only exact options keep a
            // reader a data reader, short ones included.
            "mapfile -C 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "readarray -tC 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "mapfile -c 1 -C \"$CB\" lines <<'EOF'\ngit commit -n -m x\nEOF",
            "head -z <<'EOF'\ngit commit -n -m x\nEOF",
            "cut -z -f1 <<'EOF'\ngit commit -n -m x\nEOF",
            // Review note: `cat`, `grep` or `rg` redefined in the command.
            "cat() { git commit --no-verify -m x; }; cat > notes.md <<'EOF'\n--no-verify\nEOF",
            "function cat { bash; }; cat > notes.md <<'EOF'\ngit commit --no-verify -m x\nEOF",
            "shopt -s expand_aliases; alias grep='sh -c'; grep 'git commit --no-verify -m x' f",
            "PATH=/tmp/evil:$PATH; cat > notes.md <<'EOF'\ngit commit --no-verify -m x\nEOF",
            "export PATH=/tmp/evil:$PATH; grep -- --no-verify f",
            "hash -p /bin/sh cat; cat > notes.md <<'EOF'\ngit commit --no-verify -m x\nEOF",
            ". ./env.sh; cat > notes.md <<'EOF'\n--no-verify\nEOF",
            // Review note: an option bash builds by expansion.
            "o=-C; mapfile $o 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "X=C; mapfile -$X 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "mapfile -{C,} 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "mapfile `echo -C` 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "mapfile -[C] 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "cat $opt <<'EOF'\ngit commit -n -m x\nEOF",
            "head -$N <<'EOF'\ngit commit -n -m x\nEOF",
            // Review note: tilde, extglob and brace forms.
            "mapfile ~ 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "shopt -s extglob; mapfile -@(C) 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "mapfile -!(t) 'git commit -n -m x' -c 1 lines <<'EOF'\nx\nEOF",
            "cat -{v,} <<'EOF'\ngit commit -n -m x\nEOF",
            "cat ~ <<'EOF'\ngit commit -n -m x\nEOF",
            // Review note: a substitution inside an extglob, and `!(` at the
            // command word.
            "ls !($(git commit -n -m x))",
            "mapfile -@(`git commit -n -m x`) lines <<'EOF'\nx\nEOF",
            "!(git commit -n -m x)",
            "ls @(#$(git commit -n -m x))",
            "cat > @(#$(git commit -n -m x)) <<'EOF'\nx\nEOF",
            "X=@(#$(git commit -n -m x)) ls",
            "mapfile -@(C) lines <<'EOF'\nx\nEOF\ngit status",
            "ls @($'\\''$(git commit -n -m x)'')",
            "mapfile -@(C) lines 'git commit -n -m x' <<'EOF'\nx\nEOF",
            "ls *(a|#`git commit -n -m x`)",
            "ls @(#<(git commit -n -m x))",
            "ls !(x#>(git commit -n -m x))",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
    }

    /// An unquoted heredoc body runs its `$(...)` and backtick
    /// substitutions; a quoted one is data. `<<` ends the body only at
    /// the delimiter itself, `<<-` also after leading tabs.
    #[test]
    fn heredoc_substitutions_are_commands() {
        for cmd in [
            "cat <<EOF\n$(git commit -n -m x)\nEOF",
            "cat <<EOF\n`git commit -n -m x`\nEOF",
            "cat <<EOF > f\n${X:-$(git push -n origin x)}\nEOF",
            "cat <<EOF\n\tEOF\n'\nEOF\ngit commit -n -m x #'",
            // A `\c` outside a literal body still denies.
            "cat <<EOF\n\\cdot\nEOF\ngit status",
            "echo -e 'x\\c'; git status",
            "sh <<'EOF'\nprintf '\\c'; git commit -n -m x\nEOF",
        ] {
            assert!(deny(cmd), "{cmd}");
        }
        for cmd in [
            "cat <<'EOF'\n$(git commit -n -m x)\nEOF",
            "cat <<EOF\n\\$(git commit -n -m x)\nEOF",
            "cat <<-EOF\n\tbody\n\tEOF\necho done",
            // A `\c` in a literal body is a character (LaTeX `\cdot`).
            "cd /w/repo && cat >> t.rs <<'EOF'\nassert_eq!(r, \"2 \\\\cdot x\");\nEOF\ngit diff --stat",
            "git commit -F - <<'EOF'\nfix: C:\\code\nEOF",
        ] {
            assert_eq!(bash_ruling(&ctx(), cmd), Ruling::Allow, "{cmd}");
        }
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
