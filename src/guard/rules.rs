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

/// The command a wrapper runs: wrappers, their options and (for `env`)
/// assignments stripped. `timeout` also drops its duration, `flock` its
/// lock file.
#[must_use]
pub fn strip_wrappers(words: &[String]) -> &[String] {
    let mut w = words;
    'outer: loop {
        let Some(first) = w.first() else {
            return w;
        };
        let name = basename(first);
        let Some((_, takes_value)) = WRAPPERS.iter().find(|(n, _)| *n == name) else {
            return w;
        };
        let mut i = 1;
        while i < w.len() {
            let a = w[i].as_str();
            if a == "--" {
                i += 1;
                break;
            }
            if name == "env" && shell::is_assignment(a) {
                i += 1;
                continue;
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
        // Positional arguments that come before the command.
        let skip = match name {
            "timeout" | "flock" | "chrt" | "taskset" => 1,
            _ => 0,
        };
        i += skip;
        if i >= w.len() {
            return &w[w.len()..];
        }
        w = &w[i..];
        continue 'outer;
    }
}

/// The commands a simple command runs: itself after wrappers, plus the
/// script of `sh -c`/`bash -c`/`eval` parsed again.
fn expand(cmd: &SimpleCommand, depth: usize, out: &mut Vec<Vec<String>>) {
    let words = strip_wrappers(&cmd.words).to_vec();
    if words.is_empty() {
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
                expand(&inner, depth + 1, out);
            }
        }
    }
    out.push(words);
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
/// clusters included; values of options that take one are skipped.
fn has_short_n(sub: &str, args: &[String]) -> bool {
    let (short_value, long_value): (&str, &[&str]) = match sub {
        "commit" => (
            "mFcCt",
            &[
                "--message",
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
            &["--push-option", "--repo", "--receive-pack", "--exec"],
        ),
        "am" => (
            "",
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

/// R25/R26 for a Bash command.
#[must_use]
pub fn bash_ruling(ctx: &Context, command: &str) -> Ruling {
    let norm = normalize(command);
    for (needle, why) in DENY_SUBSTRINGS {
        if norm.contains(needle) {
            return Ruling::Deny(format!("{why} (R25)"));
        }
    }
    let mut ruling = Ruling::Allow;
    // `cd <dir>` changes where later relative paths point (best effort).
    let mut here = ctx.clone();
    for cmd in shell::parse(command) {
        if let [cd, dir] = cmd.words.as_slice()
            && cd == "cd"
        {
            here.cwd = resolve_path(&here, dir);
        }
        let ctx = &here;
        let mut runs = Vec::new();
        expand(&cmd, 0, &mut runs);
        if runs.is_empty() {
            ruling = ruling.max(command_ruling(ctx, &[], &cmd.redirects));
        }
        for (k, words) in runs.iter().enumerate() {
            // Redirections belong to the outer command only.
            let redirects: &[shell::Redirect] = if k + 1 == runs.len() {
                &cmd.redirects
            } else {
                &[]
            };
            ruling = ruling.max(command_ruling(ctx, words, redirects));
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
        expand(cmd, 0, &mut runs);
        runs.iter().any(|w| {
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
