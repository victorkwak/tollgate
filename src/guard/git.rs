//! git and tollgate commands (G4, G7, R25, R26).
//!
//! Gated subcommands (commit, merge, am, cherry-pick, revert, rebase,
//! pull, push, send-pack) and every tollgate subcommand use a closed
//! shape: literal words (the `"$(cat <<'EOF' ... EOF)"` message idiom is
//! literal), a known cwd, only listed `-c` keys and variables, and flags
//! checked by option position, so a message never decides anything. Other
//! subcommands run as written, except the ref and remote writes of G7.

use std::path::{Path, PathBuf};

use super::cmds;
use super::rules::{basename, is_tollgate};
use super::shell::{Part, Word};
use super::walk::{Cwd, EnvSet, Feed, Frame, Target, Via, W, Walker};

/// Subcommands that run a gate hook or move a branch (G4).
pub const GATED: &[&str] = &[
    "commit",
    "merge",
    "am",
    "cherry-pick",
    "revert",
    "rebase",
    "pull",
    "push",
    "send-pack",
];

/// Subcommands that can wait in a gate hook (R28).
const WAITING: &[&str] = &[
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

/// git's commands (2.56) and `lfs`. Anything else is an alias or an
/// external command the guard does not follow.
pub const KNOWN: &[&str] = &[
    "add",
    "am",
    "annotate",
    "apply",
    "archive",
    "backfill",
    "bisect",
    "blame",
    "branch",
    "bugreport",
    "bundle",
    "cat-file",
    "check-attr",
    "check-ignore",
    "check-mailmap",
    "check-ref-format",
    "checkout",
    "checkout-index",
    "cherry",
    "cherry-pick",
    "citool",
    "clean",
    "clone",
    "column",
    "commit",
    "commit-graph",
    "commit-tree",
    "config",
    "count-objects",
    "credential",
    "credential-cache",
    "credential-store",
    "describe",
    "diagnose",
    "diff",
    "diff-files",
    "diff-index",
    "diff-pairs",
    "diff-tree",
    "difftool",
    "fast-export",
    "fast-import",
    "fetch",
    "fetch-pack",
    "filter-branch",
    "fmt-merge-msg",
    "for-each-ref",
    "for-each-repo",
    "format-patch",
    "fsck",
    "fsmonitor--daemon",
    "gc",
    "get-tar-commit-id",
    "grep",
    "gui",
    "hash-object",
    "help",
    "hook",
    "http-backend",
    "imap-send",
    "index-pack",
    "init",
    "instaweb",
    "interpret-trailers",
    "last-modified",
    "lfs",
    "log",
    "ls-files",
    "ls-remote",
    "ls-tree",
    "mailinfo",
    "mailsplit",
    "maintenance",
    "merge",
    "merge-base",
    "merge-file",
    "merge-index",
    "merge-octopus",
    "merge-one-file",
    "merge-ours",
    "merge-recursive",
    "merge-resolve",
    "merge-subtree",
    "merge-tree",
    "mergetool",
    "mktag",
    "mktree",
    "multi-pack-index",
    "mv",
    "name-rev",
    "notes",
    "pack-objects",
    "pack-redundant",
    "pack-refs",
    "patch-id",
    "prune",
    "prune-packed",
    "pull",
    "push",
    "range-diff",
    "read-tree",
    "rebase",
    "receive-pack",
    "reflog",
    "refs",
    "remote",
    "repack",
    "replace",
    "replay",
    "repo",
    "request-pull",
    "rerere",
    "reset",
    "restore",
    "rev-list",
    "rev-parse",
    "revert",
    "rm",
    "send-email",
    "send-pack",
    "shortlog",
    "show",
    "show-branch",
    "show-index",
    "show-ref",
    "sparse-checkout",
    "stage",
    "stash",
    "status",
    "stripspace",
    "submodule",
    "switch",
    "symbolic-ref",
    "tag",
    "unpack-file",
    "unpack-objects",
    "update-index",
    "update-ref",
    "update-server-info",
    "upload-archive",
    "upload-pack",
    "var",
    "verify-commit",
    "verify-pack",
    "verify-tag",
    "version",
    "whatchanged",
    "worktree",
    "write-tree",
];

/// Subcommands xargs, find -exec and parallel may run: extra arguments
/// cannot make them move a ref or run code (G2a).
const SAFE_ELSEWHERE: &[&str] = &[
    "add",
    "rm",
    "mv",
    "restore",
    "status",
    "log",
    "diff",
    "show",
    "rev-parse",
    "ls-files",
    "ls-tree",
    "cat-file",
    "grep",
    "blame",
    "describe",
    "shortlog",
    "rev-list",
    "for-each-ref",
    "merge-base",
    "name-rev",
    "show-ref",
    "check-ignore",
    "check-attr",
    "diff-tree",
    "diff-files",
    "diff-index",
    "hash-object",
    "annotate",
    "version",
    "help",
];

/// `-c` keys allowed on gated commands (G4); `advice.*` too.
const GATED_KEYS: &[&str] = &[
    "core.editor",
    "sequence.editor",
    "user.name",
    "user.email",
    "commit.gpgsign",
    "color.ui",
    "core.pager",
    "pull.rebase",
    "rebase.autostash",
];

/// The allowed shape, for deny messages.
const SHAPE: &str = "write it as: cd /abs/repo && git <subcommand> <literal words>, with a message as -m \"...\", -F <file> or -F - <<'EOF' (G4)";

/// `core.fsmonitor=<false>`: a `-c` that turns the fsmonitor program off
/// (a bare `-c core.fsmonitor` means true).
fn fsmonitor_off(c: &str) -> bool {
    c.split_once('=').is_some_and(|(k, v)| {
        k.eq_ignore_ascii_case("core.fsmonitor")
            && matches!(
                v.to_ascii_lowercase().as_str(),
                "false" | "no" | "off" | "0"
            )
    })
}

/// What a config key does when a command line sets it.
enum KeyClass {
    /// Removes or replaces the hooks, or runs a program on any command.
    Deny(&'static str),
    /// Changes which server a remote reaches, or how (R26, G7, X1).
    Ask(&'static str),
    /// Git runs its value (editor, pager, diff and filter drivers, ...).
    Runs(Value),
    Plain,
}

/// How git runs a config value (item 21).
#[derive(Clone, Copy)]
enum Value {
    /// As [`cmds::Runs`].
    As(cmds::Runs),
    /// A credential helper: `!code`, an absolute program path with
    /// arguments, or `git-credential-<value>`; all through a shell, with
    /// arguments.
    Helper,
    /// `submodule.<name>.update`: `!code` is shell code.
    SubmoduleUpdate,
    /// `protocol.allow` and `protocol.ext.allow`: anything but `never`
    /// can turn on the `ext::` transport, which runs a command.
    ExtProtocol,
}

const fn shell(args: bool) -> KeyClass {
    KeyClass::Runs(Value::As(cmds::Runs::Shell { args }))
}

const PROGRAM: KeyClass = KeyClass::Runs(Value::As(cmds::Runs::Program));

/// Config keys whose value git runs (item 21), given in lowercase:
/// `section.key` or `section.<sub>.key`.
fn runs_key(k: &str) -> Option<KeyClass> {
    let parts: Vec<&str> = k.split('.').collect();
    let (Some(&section), Some(&last)) = (parts.first(), parts.last()) else {
        return None;
    };
    let sub = parts.len() > 2;
    let c = match (section, last) {
        ("core", "editor") | ("sequence", "editor") => shell(true),
        ("core", "askpass") => PROGRAM,
        ("core", "pager") | ("pager", _) | ("interactive", "difffilter") => shell(false),
        ("diff", "external") => shell(true),
        ("diff", "command" | "textconv") if sub => shell(true),
        ("filter", "clean" | "smudge" | "process") if sub => shell(false),
        ("merge", "driver") if sub => shell(false),
        ("mergetool" | "difftool" | "guitool", "cmd") if sub => shell(false),
        ("man" | "browser", "cmd") if sub => shell(true),
        ("mergetool" | "difftool" | "man" | "browser", "path") if sub => PROGRAM,
        ("gpg", "program") => PROGRAM,
        ("gpg", "defaultkeycommand") if sub => shell(false),
        ("credential", "helper") => KeyClass::Runs(Value::Helper),
        ("submodule", "update") if sub => KeyClass::Runs(Value::SubmoduleUpdate),
        ("protocol", "allow") if !sub || parts[1] == "ext" => KeyClass::Runs(Value::ExtProtocol),
        ("imap", "tunnel") | ("instaweb", "httpd" | "browser") => shell(true),
        ("sendemail", _) if last.ends_with("cmd") || last == "smtpserver" => shell(true),
        ("lfs", "path") if sub => PROGRAM,
        ("lfs", "clean" | "smudge") if sub => shell(false),
        ("uploadpack", "packobjectshook") => {
            KeyClass::Deny("runs a program for every pack git serves")
        }
        ("core", "alternaterefscommand") => {
            KeyClass::Deny("runs a program for every fetch from a repo with alternates")
        }
        ("hook", _) => KeyClass::Deny("defines a hook, which runs a program on git events"),
        _ if last.ends_with("cmd") || last.ends_with("command") || last.ends_with("program") => {
            // A key this list does not name yet: read its value as code.
            shell(true)
        }
        _ => return None,
    };
    Some(c)
}

fn key_class(key: &str) -> KeyClass {
    let k = key.to_lowercase();
    if k.starts_with("core.hooks") {
        return KeyClass::Deny("changes the hooks git runs");
    }
    if k.starts_with("include.") || k.starts_with("includeif.") {
        return KeyClass::Deny("includes config files the guard does not read");
    }
    if k.starts_with("alias.") {
        return KeyClass::Deny("defines an alias, which can run any command");
    }
    if k == "core.fsmonitor" {
        return KeyClass::Deny("runs a program on every index read");
    }
    if k.starts_with("url.") {
        return KeyClass::Ask("rewrites remote URLs, which decide remote trust (R26, R5, R14)");
    }
    if k.starts_with("remote.")
        && ["url", "pushurl", "fetch", "uploadpack", "receivepack"]
            .iter()
            .any(|s| k.ends_with(&format!(".{s}")))
    {
        return KeyClass::Ask("changes a remote's identity, which decides remote trust (G7)");
    }
    if k == "core.sshcommand" || k == "core.gitproxy" || k.starts_with("ssh.") {
        return KeyClass::Ask("picks the program git reaches a server with (R26, X1)");
    }
    runs_key(&k).unwrap_or(KeyClass::Plain)
}

/// The shell text git runs for program value `v` of `how`, `None` when
/// it runs nothing; `Err` when the guard cannot read it as code.
fn value_code(how: Value, v: &str) -> Result<Option<String>, String> {
    let v = v.trim();
    let with_args = cmds::with_args;
    Ok(match how {
        Value::As(r) => return cmds::runs_code(r, v),
        Value::Helper => {
            if v.is_empty() {
                None
            } else if let Some(code) = v.strip_prefix('!') {
                Some(with_args(code))
            } else if v.starts_with('/') {
                Some(with_args(v))
            } else {
                // git runs its own helpers or `git-credential-<name>`
                // from PATH.
                Some(with_args(&format!("git-credential-{v}")))
            }
        }
        Value::SubmoduleUpdate => v.strip_prefix('!').map(with_args),
        Value::ExtProtocol => {
            if v.eq_ignore_ascii_case("never") {
                None
            } else {
                return Err(format!(
                    "`{v}` can turn on the ext:: transport, which runs a command"
                ));
            }
        }
    })
}

/// A gated subcommand's options: short letters with a value, short
/// letters with an optional glued value, long options with a value, and
/// whether `-n` means `--no-verify`.
struct SubOpts {
    short_val: &'static str,
    short_opt: &'static str,
    long_val: &'static [&'static str],
    n_no_verify: bool,
}

fn sub_opts(sub: &str) -> SubOpts {
    match sub {
        "commit" => SubOpts {
            short_val: "mFcCt",
            short_opt: "uS",
            long_val: &[
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
            n_no_verify: true,
        },
        "am" => SubOpts {
            short_val: "Cp",
            short_opt: "S",
            long_val: &[
                "--directory",
                "--exclude",
                "--include",
                "--resolvemsg",
                "--patch-format",
                "--quoted-cr",
                "--empty",
            ],
            n_no_verify: true,
        },
        // git push -n is --dry-run; denied with the commit and am forms
        // all the same (G4).
        "push" => SubOpts {
            short_val: "o",
            short_opt: "",
            long_val: &["--repo", "--receive-pack", "--exec", "--push-option"],
            n_no_verify: true,
        },
        "merge" => SubOpts {
            short_val: "mFsX",
            short_opt: "S",
            long_val: &[
                "--message",
                "--file",
                "--strategy",
                "--strategy-option",
                "--into-name",
                "--cleanup",
            ],
            n_no_verify: false,
        },
        "pull" => SubOpts {
            short_val: "sX",
            short_opt: "rS",
            long_val: &[
                "--strategy",
                "--strategy-option",
                "--depth",
                "--deepen",
                "--shallow-since",
                "--shallow-exclude",
                "--upload-pack",
                "--negotiation-tip",
                "--server-option",
                "--jobs",
            ],
            n_no_verify: false,
        },
        "rebase" => SubOpts {
            short_val: "sXx",
            short_opt: "S",
            long_val: &[
                "--onto",
                "--strategy",
                "--strategy-option",
                "--exec",
                "--whitespace",
            ],
            n_no_verify: false,
        },
        // cherry-pick, revert (-n is --no-commit), send-pack.
        _ => SubOpts {
            short_val: "mX",
            short_opt: "S",
            long_val: &["--mainline", "--strategy", "--strategy-option", "--cleanup"],
            n_no_verify: false,
        },
    }
}

/// An option whose value a program runs (item 21).
struct OptSpec {
    short: Option<char>,
    long: &'static str,
    /// Characters of `long` git needs to take a prefix of it.
    min: usize,
    /// The value is only glued (`-Ocmd`, `--opt=cmd`); alone, the option
    /// takes none.
    glued_only: bool,
    kind: OptKind,
}

#[derive(Clone, Copy)]
enum OptKind {
    /// Denied whatever the value is.
    Deny,
    /// The value runs as this.
    Runs(cmds::Runs),
    /// A `key=value` config entry the command writes (`clone -c`).
    Config,
}

const fn opt(short: Option<char>, long: &'static str, min: usize, kind: OptKind) -> OptSpec {
    OptSpec {
        short,
        long,
        min,
        glued_only: false,
        kind,
    }
}

/// The options of `sub` whose value git runs (item 21), and the short
/// letters of `sub` that take a value (the rest of the word, or the next
/// word).
fn program_opt_specs(sub: &str) -> Option<(&'static [OptSpec], &'static str)> {
    const SHELL_ARGS: OptKind = OptKind::Runs(cmds::Runs::Shell { args: true });
    const DIFFTOOL: &[OptSpec] = &[opt(Some('x'), "--extcmd", 3, SHELL_ARGS)];
    const GREP: &[OptSpec] = &[OptSpec {
        short: Some('O'),
        long: "--open-files-in-pager",
        min: 4,
        glued_only: true,
        kind: SHELL_ARGS,
    }];
    const CLONE: &[OptSpec] = &[
        opt(Some('u'), "--upload-pack", 3, OptKind::Deny),
        opt(Some('c'), "--config", 4, OptKind::Config),
    ];
    const UPLOAD_PACK: &[OptSpec] = &[
        opt(None, "--upload-pack", 3, OptKind::Deny),
        opt(None, "--exec", 3, OptKind::Deny),
    ];
    const ARCHIVE: &[OptSpec] = &[opt(None, "--exec", 3, OptKind::Deny)];
    Some(match sub {
        "difftool" => (DIFFTOOL, "tx"),
        "grep" => (GREP, "efABCmO"),
        "clone" => (CLONE, "obucj"),
        "ls-remote" | "fetch-pack" => (UPLOAD_PACK, ""),
        "archive" => (ARCHIVE, ""),
        _ => return None,
    })
}

/// `abbrev` names long option `full` (git takes unique prefixes): at least
/// `min` characters of it.
fn names(abbrev: &str, full: &str, min: usize) -> bool {
    abbrev.len() >= min && full.starts_with(abbrev)
}

/// git's global options before the subcommand.
#[derive(Default)]
struct Globals {
    /// `-C` values (`None`: not literal).
    dirs: Vec<Option<String>>,
    /// `-c` values.
    configs: Vec<String>,
    /// `--config-env` keys.
    config_env: Vec<String>,
    /// `--git-dir`, `--work-tree`, `--exec-path=`, ...
    redirect: Option<String>,
    unknown: Option<String>,
    no_run: bool,
    /// The subcommand and its index in argv.
    sub: Option<(usize, String)>,
}

impl Walker<'_> {
    /// G4, G7, R25, R26 for a git command.
    pub(super) fn git(&mut self, argv: &[Word], env: Vec<EnvSet>, f: &Frame, via: Via) -> W {
        self.saw_git = true;
        let lits = self.lits(argv);
        if let Some(u) = lits
            .iter()
            .flatten()
            .find(|l| l.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("ext::")))
        {
            return Err(format!(
                "git with `{u}`: the ext:: transport runs a command (G3, item 21)"
            ));
        }
        let g = parse_globals(argv, &lits)?;
        let Some((si, sub)) = g.sub.clone() else {
            if via == Via::Elsewhere && !g.no_run {
                return Err(
                    "xargs, find -exec and parallel run git with the subcommand from elsewhere (G2)".into(),
                );
            }
            self.env_check(&env, Target::Git)?;
            return self.git_configs(&g, false);
        };
        if !KNOWN.contains(&sub.as_str()) {
            return Err(format!(
                "git {sub}: not a git command the guard knows; aliases and external commands are not followed, so write the full subcommand (G4)"
            ));
        }
        let gated = GATED.contains(&sub.as_str());
        if WAITING.contains(&sub.as_str()) {
            self.long = true;
        }
        if via == Via::Elsewhere && (gated || !SAFE_ELSEWHERE.contains(&sub.as_str())) {
            return Err(format!(
                "xargs, find -exec and parallel run git {sub} with arguments from elsewhere; run it directly (G2)"
            ));
        }
        if let Some(o) = &g.unknown {
            return Err(format!("git {o}: an option the guard does not know (G4)"));
        }
        self.env_check(&env, if gated { Target::GatedGit } else { Target::Git })?;
        self.git_configs(&g, gated)?;
        let args = &argv[si + 1..];
        let arg_lits = &lits[si + 1..];
        if !gated {
            if g.redirect
                .as_deref()
                .is_some_and(|r| r.starts_with("--exec-path"))
            {
                return Err(
                    "git --exec-path=<dir> runs git's programs from that dir (G4, X1)".into(),
                );
            }
            self.program_opts(&sub, args, arg_lits)?;
            let dir = self.git_dir(&g.dirs);
            return self.plain_git(&sub, args, arg_lits, f, dir.as_deref());
        }
        if let Some(r) = &g.redirect {
            return Err(format!(
                "git {r} on git {sub} points git at another repo or program; {SHAPE}"
            ));
        }
        if let Some(k) = lits.iter().position(Option::is_none) {
            return Err(format!(
                "git {sub} with `{}`, a word bash builds at run time; {SHAPE}",
                argv[k].raw
            ));
        }
        let Some(dir) = self.git_dir(&g.dirs) else {
            return Err(format!(
                "git {sub} after a cd the guard cannot follow; {SHAPE} (G8)"
            ));
        };
        if self.stdin_of(f) == Feed::Doc(None) {
            return Err(format!(
                "git {sub} reads a heredoc with expansions; quote the delimiter (<<'EOF'); {SHAPE}"
            ));
        }
        if sub == "send-pack" {
            return Err("git send-pack skips the pre-push gate (R25, G4)".into());
        }
        let words: Vec<String> = arg_lits.iter().flatten().cloned().collect();
        let positionals = self.gated_flags(&sub, &words)?;
        if sub == "push" {
            self.push_dot(&positionals, &dir)?;
        }
        Ok(())
    }

    /// `-c` and `--config-env` (G4 on gated commands, R25/R26 on all).
    fn git_configs(&mut self, g: &Globals, gated: bool) -> W {
        for c in &g.configs {
            let key = c.split('=').next().unwrap_or(c);
            if fsmonitor_off(c) {
                // Turns the program off; agents set it to keep a stale
                // daemon out of scripted git calls.
                continue;
            }
            match key_class(key) {
                KeyClass::Deny(why) => return Err(format!("git -c {c}: {why} (R25)")),
                KeyClass::Ask(why) if !gated => self.ask(format!("git -c {c}: {why}")),
                KeyClass::Runs(how) => {
                    let v = c.split_once('=').map_or("", |(_, v)| v);
                    let what = format!("git -c {key}");
                    let code =
                        value_code(how, v).map_err(|e| format!("{what}: {e} (G3, item 21)"))?;
                    if let Some(code) = code {
                        self.program_code(&code, &what)?;
                    }
                }
                _ => {}
            }
            let lower = key.to_lowercase();
            if gated && !(GATED_KEYS.contains(&lower.as_str()) || lower.starts_with("advice.")) {
                return Err(format!(
                    "git -c {c} on a gated command: only {} and advice.* may be set there (G4)",
                    GATED_KEYS.join(", ")
                ));
            }
        }
        for key in &g.config_env {
            if gated {
                return Err(format!(
                    "git --config-env {key} on a gated command: the value comes from a variable the guard cannot see (G4)"
                ));
            }
            match key_class(key) {
                KeyClass::Deny(why) => return Err(format!("git --config-env {key}: {why} (R25)")),
                KeyClass::Ask(why) => self.ask(format!("git --config-env {key}: {why}")),
                KeyClass::Runs(_) => {
                    return Err(format!(
                        "git --config-env {key}: git runs its value, which comes from a variable the guard cannot see (G3, item 21)"
                    ));
                }
                KeyClass::Plain => {}
            }
        }
        Ok(())
    }

    /// Item 21: options of non-gated subcommands whose value git runs
    /// (`difftool -x`, `grep -O`, `clone -u`, `ls-remote --upload-pack`,
    /// `archive --exec`), `clone -c` keys, and subcommands that run code
    /// or commands the guard does not follow.
    fn program_opts(&mut self, sub: &str, args: &[Word], lits: &[Option<String>]) -> W {
        let deny_sub = match sub {
            "filter-branch" => Some("runs shell filters and rewrites branches without a gate"),
            "for-each-repo" => Some("runs a git command in repos named by config"),
            "send-email" => Some("sends mail and runs programs named by its options"),
            "instaweb" => Some("starts a web server and a browser named by its options"),
            _ => None,
        };
        if let Some(why) = deny_sub {
            return Err(format!("git {sub} {why} (G3, item 21)"));
        }
        let Some((spec, short_val)) = program_opt_specs(sub) else {
            return Ok(());
        };
        // A word bash builds is checked by its value when the guard knows
        // it and bash does not split it into several.
        let vals: Vec<Option<String>> = lits
            .iter()
            .zip(args)
            .map(|(l, w)| {
                l.clone().or_else(|| {
                    let unquoted = w
                        .parts
                        .iter()
                        .any(|p| !matches!(p, Part::Lit(_) | Part::Single(_) | Part::Double(_)));
                    self.resolve(w).filter(|v| {
                        !(unquoted && v.contains(|c: char| c.is_whitespace() || "*?[".contains(c)))
                    })
                })
            })
            .collect();
        let mut k = 0;
        while k < vals.len() {
            let Some(a) = vals[k].as_deref() else {
                // An unknown word can be an option, unless it starts with
                // literal text that is not `-`, or is the value of `-e`.
                let (prefix, _) = args[k].literal_prefix();
                let pattern =
                    sub == "grep" && k > 0 && matches!(vals[k - 1].as_deref(), Some("-e" | "-f"));
                if (prefix.is_empty() || prefix.starts_with('-')) && !pattern {
                    return Err(format!(
                        "git {sub} with `{}`, a word bash builds at run time where an option can run a program; put --end-of-options before it{} (G3, item 21)",
                        args[k].raw,
                        if sub == "grep" {
                            ", or give a pattern with -e"
                        } else {
                            ""
                        }
                    ));
                }
                k += 1;
                continue;
            };
            if a == "--" || a == "--end-of-options" {
                break;
            }
            let mut found: Vec<(&OptSpec, Option<String>)> = Vec::new();
            let mut takes_next = false;
            if let Some(long) = a.strip_prefix("--") {
                let (name, glued) = match long.split_once('=') {
                    Some((n, v)) => (format!("--{n}"), Some(v.to_owned())),
                    None => (a.to_owned(), None),
                };
                for o in spec {
                    if names(&name, o.long, o.min) {
                        let v = if glued.is_some() || o.glued_only {
                            glued.clone()
                        } else {
                            takes_next = true;
                            vals.get(k + 1).cloned().flatten()
                        };
                        found.push((o, v));
                    }
                }
            } else if let Some(cluster) = a.strip_prefix('-') {
                for (j, c) in cluster.char_indices() {
                    if !short_val.contains(c) {
                        continue;
                    }
                    let rest = &cluster[j + c.len_utf8()..];
                    let o = spec.iter().find(|o| o.short == Some(c));
                    let glued_only = o.is_some_and(|o| o.glued_only);
                    let v = if !rest.is_empty() {
                        Some(rest.to_owned())
                    } else if glued_only {
                        None
                    } else {
                        takes_next = true;
                        vals.get(k + 1).cloned().flatten()
                    };
                    if let Some(o) = o {
                        found.push((o, v));
                    }
                    break;
                }
            }
            for (o, v) in found {
                let shown = format!("git {sub} {}", o.long);
                match (o.kind, v) {
                    (OptKind::Deny, _) => {
                        return Err(format!(
                            "{shown} runs a program of the command's choosing (G3, item 21)"
                        ));
                    }
                    // `grep -O` alone: the session's own pager.
                    (OptKind::Runs(_), None) if o.glued_only => {}
                    (_, None) => {
                        return Err(format!(
                            "{shown} with a value bash builds at run time (G3, item 21)"
                        ));
                    }
                    (OptKind::Config, Some(c)) => self.clone_config(&c)?,
                    (OptKind::Runs(r), Some(v)) => {
                        let code = cmds::runs_code(r, &v)
                            .map_err(|e| format!("{shown}: {e} (G3, item 21)"))?;
                        if let Some(code) = code {
                            self.program_code(&code, &shown)?;
                        }
                    }
                }
            }
            k += if takes_next { 2 } else { 1 };
        }
        Ok(())
    }

    /// `git clone -c key=value`: git sets it for the clone and writes it
    /// into the new repo's config, where later commands read it.
    fn clone_config(&mut self, c: &str) -> W {
        let key = c.split('=').next().unwrap_or(c);
        match key_class(key) {
            KeyClass::Deny(why) => Err(format!("git clone -c {c}: {why} (R25)")),
            KeyClass::Ask(why) => {
                self.ask(format!("git clone -c {c}: {why}"));
                Ok(())
            }
            KeyClass::Runs(_) => {
                self.ask(format!(
                    "git clone -c {c} writes a value git runs into the new repo's config (item 21)"
                ));
                Ok(())
            }
            KeyClass::Plain => Ok(()),
        }
    }

    fn stdin_of(&self, f: &Frame) -> Feed {
        f.stdin.clone()
    }

    /// The dir git runs in: the cwd with each `-C` applied; `None` when
    /// it cannot be known.
    fn git_dir(&self, dirs: &[Option<String>]) -> Option<PathBuf> {
        let mut cur = match self.cwd() {
            Cwd::Known(p) => Some(p.clone()),
            Cwd::Unknown => None,
        };
        for d in dirs {
            let d = d.as_deref()?;
            if d.is_empty() {
                continue;
            }
            cur = if Path::new(d).is_absolute() {
                self.abs_path(d)
            } else {
                cur.map(|c| super::paths::canon(&super::paths::lexical(&c, Path::new(d))))
            };
        }
        cur
    }

    /// Flags of a gated subcommand by option position (G4, item 13b):
    /// `--no-verify` and its abbreviations, `-n` where it means no-verify,
    /// options that run programs. Returns the positional words.
    fn gated_flags(&mut self, sub: &str, args: &[String]) -> Result<Vec<String>, String> {
        let spec = sub_opts(sub);
        let mut pos = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = args[i].as_str();
            i += 1;
            if a == "--" {
                pos.extend(args[i..].iter().cloned());
                break;
            }
            if a.starts_with("--") {
                let (name, glued) = match a.split_once('=') {
                    Some((n, v)) => (n, Some(v)),
                    None => (a, None),
                };
                if names(name, "--no-verify", "--no-v".len()) {
                    return Err(format!(
                        "git {sub} {a}: --no-verify (or an abbreviation of it) skips the gate hooks (R25, G4)"
                    ));
                }
                let takes = spec.long_val.contains(&name);
                let value = if takes && glued.is_none() {
                    let v = args.get(i).cloned();
                    i += 1;
                    v
                } else {
                    glued.map(str::to_owned)
                };
                match sub {
                    "push" if names(name, "--receive-pack", 5) || names(name, "--exec", 4) => {
                        return Err(format!(
                            "git push {name} runs a program of the command's choosing (G4)"
                        ));
                    }
                    "pull" if names(name, "--upload-pack", 4) => {
                        return Err(
                            "git pull --upload-pack runs a program of the command's choosing (G4)"
                                .into(),
                        );
                    }
                    "rebase" if names(name, "--exec", 4) => {
                        let code = value.unwrap_or_default();
                        let frame = Frame {
                            stdin: Feed::Unknown,
                            env: Vec::new(),
                        };
                        self.code(&code, true, &frame, "git rebase --exec")?;
                    }
                    _ => {}
                }
                continue;
            }
            if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
                for (k, c) in cluster.char_indices() {
                    if c == 'n' && spec.n_no_verify {
                        return Err(format!("git {sub} -n skips the gate hooks (R25, G4)"));
                    }
                    let rest = &cluster[k + c.len_utf8()..];
                    if spec.short_opt.contains(c) {
                        break;
                    }
                    if spec.short_val.contains(c) {
                        let value = if rest.is_empty() {
                            let v = args.get(i).cloned();
                            i += 1;
                            v
                        } else {
                            Some(rest.to_owned())
                        };
                        if sub == "rebase" && c == 'x' {
                            let frame = Frame {
                                stdin: Feed::Unknown,
                                env: Vec::new(),
                            };
                            self.code(&value.unwrap_or_default(), true, &frame, "git rebase -x")?;
                        }
                        break;
                    }
                }
                continue;
            }
            pos.push(a.to_owned());
        }
        Ok(pos)
    }

    /// G7: `git push . <src>:<dst>` writes a local ref.
    fn push_dot(&mut self, pos: &[String], dir: &Path) -> W {
        let Some((repo, specs)) = pos.split_first() else {
            return Ok(());
        };
        if repo != "." {
            return Ok(());
        }
        for s in specs {
            let s = s.trim_start_matches('+');
            let dst = s.split_once(':').map_or(s, |(_, d)| d);
            self.ref_write(dst, Some(dir), "git push .")?;
        }
        Ok(())
    }

    /// G7: writing ref `r` (a full name, or a branch name).
    fn ref_write(&mut self, r: &str, dir: Option<&Path>, how: &str) -> W {
        let l = r.to_lowercase();
        if l == "refs/remotes" || l.starts_with("refs/remotes/") {
            return Err(format!(
                "{how} writes {r}: remote-tracking refs come only from fetches of their remote (G7, item 2)"
            ));
        }
        let branch = l.strip_prefix("refs/heads/").unwrap_or(&l).to_owned();
        let anchors = match dir {
            Some(d) => self.anchors(d),
            None => vec!["main".into(), "master".into()],
        };
        if anchors.iter().any(|a| a.to_lowercase() == branch)
            || (!l.starts_with("refs/") && self.ctx.full_refs.is_match(&branch))
        {
            return Err(format!(
                "{how} moves {r}, a policy anchor or full ref; it moves only through tollgate merge and the push gate (G7)"
            ));
        }
        Ok(())
    }

    /// Subcommands that are not gated: G7 ref and remote writes, R25 and
    /// R26.
    fn plain_git(
        &mut self,
        sub: &str,
        args: &[Word],
        lits: &[Option<String>],
        f: &Frame,
        dir: Option<&Path>,
    ) -> W {
        let all_lit = || -> Result<Vec<String>, String> {
            lits.iter()
                .zip(args)
                .map(|(l, w)| {
                    l.clone().ok_or_else(|| {
                        format!("git {sub} with `{}`, a word bash builds at run time, where it names a ref or remote (G7)", w.raw)
                    })
                })
                .collect()
        };
        match sub {
            "receive-pack" => Err("git receive-pack skips the pre-push gate (R25)".into()),
            "replace" => Err("git replace changes which tree is checked (R12, R25)".into()),
            "symbolic-ref" => {
                let w = all_lit()?;
                if w.iter().any(|a| a.to_lowercase().starts_with("refs/heads")) {
                    return Err("git symbolic-ref on a branch (R10, R25)".into());
                }
                Ok(())
            }
            "update-ref" => {
                let w = all_lit()?;
                self.update_ref(&w, f, dir)
            }
            "branch" => {
                let w = all_lit()?;
                self.branch(&w, dir)
            }
            "checkout" | "switch" => {
                let force_create = |a: &str| {
                    if sub == "checkout" {
                        a == "-B"
                    } else {
                        a == "-C" || a == "--force-create" || a.starts_with("--force-create=")
                    }
                };
                for (k, l) in lits.iter().enumerate() {
                    let Some(a) = l.as_deref() else { continue };
                    if force_create(a) {
                        let name = a
                            .split_once('=')
                            .map(|(_, v)| v.to_owned())
                            .or_else(|| lits.get(k + 1).cloned().flatten());
                        let name = name.ok_or_else(|| {
                            format!("git {sub} {a} with a branch name bash builds at run time (G7)")
                        })?;
                        self.ref_write(&name, dir, &format!("git {sub} {a}"))?;
                    }
                }
                Ok(())
            }
            "worktree" => {
                if lits.first().and_then(Option::as_deref) == Some("add") {
                    for (k, l) in lits.iter().enumerate() {
                        if l.as_deref() == Some("-B") {
                            let name = lits.get(k + 1).cloned().flatten().ok_or("git worktree add -B with a branch name bash builds at run time (G7)")?;
                            self.ref_write(&name, dir, "git worktree add -B")?;
                        }
                    }
                }
                Ok(())
            }
            "fetch" => {
                let w = all_lit()?;
                self.fetch(&w, dir)
            }
            "remote" => {
                let w = all_lit()?;
                let verb = w.iter().find(|a| !a.starts_with('-'));
                if let Some(v) = verb
                    && matches!(
                        v.as_str(),
                        "add" | "remove" | "rm" | "rename" | "set-url" | "set-branches"
                    )
                {
                    self.ask(format!(
                        "git remote {v} changes a remote's identity, which decides remote trust (G7, R26)"
                    ));
                }
                Ok(())
            }
            "config" => {
                if let Some(why) = config_write(lits) {
                    self.ask(why);
                }
                Ok(())
            }
            "submodule" | "bisect" => {
                let verb = if sub == "submodule" { "foreach" } else { "run" };
                if let Some(k) = lits.iter().position(|l| l.as_deref() == Some(verb)) {
                    let rest: Option<Vec<String>> = lits[k + 1..].iter().cloned().collect();
                    let code = rest.ok_or_else(|| {
                        format!("git {sub} {verb} with code bash builds at run time (G3)")
                    })?;
                    let frame = Frame {
                        stdin: Feed::Unknown,
                        env: Vec::new(),
                    };
                    // One word is shell code; several are a command line.
                    let text = match code.as_slice() {
                        [one] if sub == "submodule" => one.clone(),
                        _ => code
                            .iter()
                            .map(|w| sh_quote(w))
                            .collect::<Vec<_>>()
                            .join(" "),
                    };
                    self.code(&text, true, &frame, &format!("git {sub} {verb}"))?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// G7: `git update-ref` (also `--stdin`).
    fn update_ref(&mut self, w: &[String], f: &Frame, dir: Option<&Path>) -> W {
        let mut pos = Vec::new();
        let mut stdin = false;
        let mut i = 0;
        while i < w.len() {
            match w[i].as_str() {
                "-m" => i += 1,
                "--stdin" => stdin = true,
                a if a.starts_with('-') => {}
                a => pos.push(a.to_owned()),
            }
            i += 1;
        }
        if stdin {
            let Feed::Doc(Some(body)) = self.stdin_of(f) else {
                return Err("git update-ref --stdin reads ref updates the guard cannot see; give them in a quoted heredoc or as arguments (G7)".into());
            };
            for line in body.split(['\n', '\0']) {
                let mut t = line.split_whitespace();
                if let (Some(verb), Some(r)) = (t.next(), t.next())
                    && !matches!(verb, "option" | "start" | "prepare" | "commit" | "abort")
                {
                    self.ref_write(r, dir, "git update-ref --stdin")?;
                }
            }
            return Ok(());
        }
        let Some(r) = pos.first() else {
            return Ok(());
        };
        if r == "HEAD"
            && let Some(b) = dir.and_then(current_branch)
        {
            return self.ref_write(&b, dir, "git update-ref HEAD");
        }
        self.ref_write(r, dir, "git update-ref")
    }

    /// G7, R25, R26: `git branch` force, rename and copy.
    fn branch(&mut self, w: &[String], dir: Option<&Path>) -> W {
        const VAL: &[&str] = &[
            "-u",
            "--set-upstream-to",
            "--contains",
            "--no-contains",
            "--merged",
            "--no-merged",
            "--points-at",
            "--sort",
            "--format",
        ];
        let mut force = false;
        let mut moves = false;
        let mut pos: Vec<&str> = Vec::new();
        let mut i = 0;
        while i < w.len() {
            let a = w[i].as_str();
            if VAL.contains(&a) {
                i += 2;
                continue;
            }
            if a == "--force" {
                force = true;
            } else if a == "--move" || a == "--copy" {
                moves = true;
            } else if let Some(c) = a
                .strip_prefix('-')
                .filter(|c| !c.starts_with('-') && !c.is_empty())
            {
                force |= c.contains('f') || c.contains('M') || c.contains('C');
                moves |= c.chars().any(|ch| "mMcC".contains(ch));
            } else if !a.starts_with('-') {
                pos.push(a);
            }
            i += 1;
        }
        if moves {
            if let Some(t) = pos.last() {
                let branch = t.strip_prefix("refs/heads/").unwrap_or(t);
                if self.ctx.full_refs.is_match(branch) {
                    return Err(format!(
                        "git branch rename/copy onto full ref {t}: use tollgate merge (R25)"
                    ));
                }
                self.ref_write(t, dir, "git branch rename/copy")?;
                self.ask(format!(
                    "git branch rename/copy to {t} moves a branch without a check (R26)"
                ));
            }
            return Ok(());
        }
        if force && let Some(n) = pos.first() {
            self.ref_write(n, dir, "git branch -f")?;
        }
        Ok(())
    }

    /// G7: fetch refspecs that write `refs/remotes/*`, or a policy anchor
    /// from a local repo.
    fn fetch(&mut self, w: &[String], dir: Option<&Path>) -> W {
        const VAL: &[&str] = &[
            "--depth",
            "--deepen",
            "--shallow-since",
            "--shallow-exclude",
            "-o",
            "--server-option",
            "--negotiation-tip",
            "--filter",
            "-j",
            "--jobs",
            "--recurse-submodules-default",
            "--submodule-prefix",
        ];
        let mut pos: Vec<&str> = Vec::new();
        let mut many = false;
        let mut i = 0;
        while i < w.len() {
            let a = w[i].as_str();
            if names(a.split('=').next().unwrap_or(a), "--upload-pack", 4) {
                return Err(
                    "git fetch --upload-pack runs a program of the command's choosing (G4)".into(),
                );
            }
            if a == "--refmap" || a.starts_with("--refmap=") {
                let v = a
                    .split_once('=')
                    .map(|(_, v)| v)
                    .or_else(|| w.get(i + 1).map(String::as_str))
                    .unwrap_or("");
                if let Some((_, dst)) = v.trim_start_matches('+').split_once(':') {
                    self.ref_write(dst, dir, "git fetch --refmap")?;
                }
                if !a.contains('=') {
                    i += 1;
                }
            } else if VAL.contains(&a) {
                i += 1;
            } else if a == "--all" || a == "--multiple" {
                many = true;
            } else if !a.starts_with('-') {
                pos.push(a);
            }
            i += 1;
        }
        if many {
            return Ok(());
        }
        let Some((repo, specs)) = pos.split_first() else {
            return Ok(());
        };
        let local = *repo == "."
            || repo.starts_with('/')
            || repo.starts_with("./")
            || repo.starts_with("../")
            || repo.starts_with('~')
            || repo.starts_with("file://");
        for s in specs {
            let Some((_, dst)) = s.trim_start_matches('+').split_once(':') else {
                continue;
            };
            let l = dst.to_lowercase();
            if l.starts_with("refs/remotes/") {
                return Err(format!(
                    "git fetch {repo} {s} writes {dst}: remote-tracking refs come only from fetches with the remote's own refspec (G7, item 2)"
                ));
            }
            if local {
                self.ref_write(dst, dir, &format!("git fetch {repo}"))?;
            }
        }
        Ok(())
    }

    /// G4 for tollgate: literal words, allowed variables; R25 subcommands.
    pub(super) fn tollgate(&mut self, argv: &[Word], env: Vec<EnvSet>, via: Via) -> W {
        self.saw_tollgate = true;
        if via == Via::Elsewhere {
            return Err(
                "xargs, find -exec and parallel run tollgate with arguments from elsewhere (G2)"
                    .into(),
            );
        }
        self.env_check(&env, Target::Tollgate)?;
        let lits = self.lits(argv);
        if let Some(k) = lits.iter().position(Option::is_none) {
            return Err(format!(
                "tollgate with `{}`, a word bash builds at run time; tollgate commands use literal words (G4)",
                argv[k].raw
            ));
        }
        let words: Vec<String> = lits.into_iter().flatten().collect();
        // clap matches subcommands exactly, but a case-insensitive file
        // system finds `TOLLGATE` too; compare in lowercase.
        let lower: Vec<String> = words[1..]
            .iter()
            .filter(|w| !w.starts_with('-'))
            .map(|w| w.to_lowercase())
            .collect();
        let pos: Vec<&str> = lower.iter().map(String::as_str).collect();
        if let Some(why) = cmds::person_only(&pos) {
            return Err(why);
        }
        match pos.as_slice() {
            [s, ..] if matches!(*s, "check" | "wait" | "merge") => {
                self.long = true;
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// G2 (item 40, review notes 11 and 1): a program the guard does not
    /// follow may run the command in its words, with any environment. A
    /// word `git` (or `git-<sub>`) with a gated subcommand, and `tollgate`
    /// with a person-only one (R25) anywhere after it, deny; a git command
    /// with another subcommand is checked as if typed. A word bash builds
    /// at run time may be git, so a gated subcommand after one denies.
    /// `values` are the words' values ([`Walker::lits`] or better).
    pub(super) fn foreign_args(
        &mut self,
        argv: &[Word],
        values: &[Option<String>],
        env: &[EnvSet],
        f: &Frame,
        via: Via,
    ) -> W {
        let gated_after = |i: usize| {
            values[i + 1..]
                .iter()
                .flatten()
                .find(|v| GATED.contains(&v.as_str()))
                .cloned()
        };
        for i in 1..argv.len() {
            let Some(word) = values[i].as_deref() else {
                if let Some(g) = gated_after(i) {
                    return Err(format!(
                        "`{}` before `{g}`: a word bash builds at run time may be git, and `{}` may run it; write the words literally, or run git directly (G1, G2, item 40)",
                        argv[i].raw, argv[0].raw
                    ));
                }
                continue;
            };
            // `--exec=git`: the value of an option.
            let w = match word.split_once('=') {
                Some((o, v)) if o.starts_with('-') => v,
                _ => word,
            };
            let base = basename(w);
            if via == Via::Elsewhere
                && (base == "git"
                    || base.starts_with("git-")
                    || base.eq_ignore_ascii_case("tollgate"))
            {
                return Err(format!(
                    "xargs, find -exec and parallel give `{}` more words from elsewhere, after {w}; run it directly (G2, item 40)",
                    argv[0].raw
                ));
            }
            if base == "git"
                || base
                    .strip_prefix("git-")
                    .is_some_and(|s| KNOWN.contains(&s))
            {
                let deny = |what: &str| {
                    Err(format!(
                        "`{}` may run {what} ({w}), and the guard does not follow it there; run git directly in the session (G2, item 40)",
                        argv[0].raw
                    ))
                };
                if self.runner_depth > 0 {
                    return deny("git under a runner");
                }
                let globals = parse_globals(&argv[i..], &values[i..]);
                match globals.as_ref().ok().and_then(|g| g.sub.clone()) {
                    Some((_, sub)) if GATED.contains(&sub.as_str()) => {
                        return deny(&format!("git {sub}"));
                    }
                    Some((_, sub)) if KNOWN.contains(&sub.as_str()) => {
                        self.git(&argv[i..], env.to_vec(), f, via)?;
                    }
                    // Not a git command line: git is data here (`pacman
                    // -S git`), unless a gated word follows options the
                    // guard cannot read.
                    _ => {
                        let unread = globals.as_ref().map_or(true, |g| g.unknown.is_some());
                        if let Some(g) = gated_after(i).filter(|_| unread) {
                            return deny(&format!("git {g}"));
                        }
                    }
                }
                continue;
            }
            if base.eq_ignore_ascii_case("tollgate") || is_tollgate(self.ctx, w) {
                let lower: Vec<String> = values[i + 1..]
                    .iter()
                    .flatten()
                    .filter(|a| !a.starts_with('-'))
                    .map(|a| a.to_lowercase())
                    .collect();
                let pos: Vec<&str> = lower.iter().map(String::as_str).collect();
                if let Some(why) = (0..pos.len()).find_map(|k| cmds::person_only(&pos[k..])) {
                    return Err(format!(
                        "{why}; `{}` may run {w} with it (G2, item 40)",
                        argv[0].raw
                    ));
                }
            }
        }
        Ok(())
    }
}

/// git's global options (before the subcommand), or a deny.
fn parse_globals(argv: &[Word], lits: &[Option<String>]) -> Result<Globals, String> {
    let mut g = Globals::default();
    let first = lits[0].as_deref().map_or("git", basename);
    if let Some(sub) = first.strip_prefix("git-") {
        g.sub = Some((0, sub.to_owned()));
        return Ok(g);
    }
    let mut i = 1;
    while i < argv.len() {
        let Some(a) = lits[i].as_deref() else {
            return Err(format!(
                "git with `{}`, a word bash builds at run time, before the subcommand; the guard cannot tell which subcommand runs (G4)",
                argv[i].raw
            ));
        };
        let value = |k: usize| lits.get(k).cloned();
        match a {
            "-C" => {
                g.dirs.push(value(i + 1).flatten());
                i += 2;
                continue;
            }
            "-c" => {
                match value(i + 1) {
                    Some(Some(v)) => g.configs.push(v),
                    Some(None) => {
                        return Err(format!(
                            "git -c `{}`: a config value bash builds at run time (G4)",
                            argv[i + 1].raw
                        ));
                    }
                    None => {}
                }
                i += 2;
                continue;
            }
            "--config-env" => {
                let v = value(i + 1)
                    .flatten()
                    .ok_or("git --config-env with a value bash builds at run time (G4)")?;
                g.config_env
                    .push(v.split('=').next().unwrap_or_default().to_owned());
                i += 2;
                continue;
            }
            "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--attr-source" => {
                g.redirect.get_or_insert_with(|| a.to_owned());
                i += 2;
                continue;
            }
            "--exec-path" | "-v" | "--version" | "-h" | "--help" | "--html-path" | "--man-path"
            | "--info-path" => g.no_run = true,
            "-p"
            | "--paginate"
            | "-P"
            | "--no-pager"
            | "--no-replace-objects"
            | "--no-lazy-fetch"
            | "--no-optional-locks"
            | "--no-advice"
            | "--bare"
            | "--literal-pathspecs"
            | "--glob-pathspecs"
            | "--noglob-pathspecs"
            | "--icase-pathspecs" => {}
            s if s.starts_with("--config-env=") => {
                let v = &s["--config-env=".len()..];
                g.config_env
                    .push(v.split('=').next().unwrap_or_default().to_owned());
            }
            s if s.starts_with("--list-cmds=") => g.no_run = true,
            s if [
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--attr-source=",
                "--exec-path=",
            ]
            .iter()
            .any(|p| s.starts_with(p)) =>
            {
                g.redirect.get_or_insert_with(|| s.to_owned());
            }
            s if s.starts_with('-') => {
                g.unknown.get_or_insert_with(|| s.to_owned());
            }
            s => {
                g.sub = Some((i, s.to_owned()));
                return Ok(g);
            }
        }
        i += 1;
    }
    Ok(g)
}

/// R26, G7: a `git config` call that writes a key that asks.
fn config_write(lits: &[Option<String>]) -> Option<String> {
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
    let mut positionals: Vec<Option<&str>> = Vec::new();
    let mut write = false;
    let mut read = false;
    let mut i = 0;
    while i < lits.len() {
        let a = lits[i].as_deref();
        i += 1;
        let Some(a) = a else {
            positionals.push(None);
            continue;
        };
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
        positionals.push(Some(a));
    }
    if lits
        .iter()
        .flatten()
        .any(|a| a == "edit" || a == "--edit" || a == "-e")
    {
        return Some("git config --edit can change core.hooksPath and remotes (R26)".into());
    }
    let write = write || (!read && positionals.len() >= 2);
    if !write {
        return None;
    }
    let Some(key) = positionals.first().copied().flatten() else {
        return Some("git config writes a key bash builds at run time (R26, G7)".into());
    };
    let k = key.to_lowercase();
    let asks = k.starts_with("core.hooks")
        || k == "core"
        || k == "url"
        || k == "ssh"
        || k == "remote"
        || k.starts_with("include")
        || k.starts_with("alias")
        || matches!(
            key_class(&k),
            KeyClass::Ask(_) | KeyClass::Deny(_) | KeyClass::Runs(_)
        )
        || (k.starts_with("remote.") && k.matches('.').count() == 1);
    asks.then(|| format!("git config writes {key} (R26, G7)"))
}

/// The branch `HEAD` names in the repo at `dir` (`.git` dir or file).
fn current_branch(dir: &Path) -> Option<String> {
    let root = dir.ancestors().find(|a| a.join(".git").exists())?;
    let dotgit = root.join(".git");
    let gitdir = if dotgit.is_file() {
        let text = std::fs::read_to_string(&dotgit).ok()?;
        let p = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        if p.is_absolute() { p } else { root.join(p) }
    } else {
        dotgit
    };
    let head = std::fs::read_to_string(gitdir.join("HEAD")).ok()?;
    head.trim()
        .strip_prefix("ref:")
        .map(|r| r.trim().to_owned())
}

/// `w` single-quoted for a shell.
fn sh_quote(w: &str) -> String {
    format!("'{}'", w.replace('\'', "'\\''"))
}
