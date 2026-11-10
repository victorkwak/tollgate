//! The rules for a `git` command line (M1, M2a, M2d, M5): the words
//! after `git`, in the positions where git reads them. Option values
//! (`-m <msg>`, `-C <dir>`, `--grep=<pat>`), words after `--` and words
//! that are only known at run time are data.

use super::cmds::Arg;
use super::rules::{Context, Ruling};

/// The git commands that can wait in a gate hook (R28).
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

/// What the rules say about one git command line.
#[derive(Debug)]
pub struct Outcome {
    pub ruling: Ruling,
    /// The subcommand can wait in a gate hook (R28).
    pub waits: bool,
    /// The values of `-C`, in order.
    pub dirs: Vec<Arg>,
    /// Paths the command writes (`git rm`, `git mv`, `git clean`, `git
    /// config --file`), each with "it is removed" (M3).
    pub writes: Vec<(Arg, bool)>,
}

/// Which options of a subcommand take a value, so that a value is never
/// read as an option or a positional.
struct Shape {
    /// Long options whose value is the next word.
    long: &'static [&'static str],
    /// Short options whose value is the rest of the cluster or the next
    /// word.
    short: &'static str,
    /// Short options whose value is only the rest of the cluster.
    attached: &'static str,
}

const COMMIT: Shape = Shape {
    long: &[
        "--message",
        "--file",
        "--reuse-message",
        "--reedit-message",
        "--fixup",
        "--squash",
        "--author",
        "--date",
        "--template",
        "--cleanup",
        "--trailer",
        "--pathspec-from-file",
    ],
    short: "mFCct",
    attached: "Su",
};
const MERGE: Shape = Shape {
    long: &[
        "--message",
        "--file",
        "--strategy",
        "--strategy-option",
        "--into-name",
        "--cleanup",
    ],
    short: "mFsX",
    attached: "S",
};
const TRANSFER_LONG: &[&str] = &[
    "--strategy",
    "--strategy-option",
    "--cleanup",
    "--depth",
    "--deepen",
    "--shallow-since",
    "--shallow-exclude",
    "--upload-pack",
    "--jobs",
    "--refmap",
    "--server-option",
    "--negotiation-tip",
    "--filter",
    "--repo",
    "--receive-pack",
    "--exec",
    "--push-option",
];
const PULL: Shape = Shape {
    long: TRANSFER_LONG,
    short: "sXjo",
    attached: "S",
};
const PUSH: Shape = Shape {
    long: TRANSFER_LONG,
    short: "o",
    attached: "",
};
const FETCH: Shape = Shape {
    long: TRANSFER_LONG,
    short: "jo",
    attached: "",
};
const AM: Shape = Shape {
    long: &[
        "--directory",
        "--exclude",
        "--include",
        "--whitespace",
        "--patch-format",
    ],
    short: "",
    attached: "SCp",
};
const BRANCH: Shape = Shape {
    long: &[
        "--set-upstream-to",
        "--contains",
        "--no-contains",
        "--merged",
        "--no-merged",
        "--points-at",
        "--sort",
        "--format",
    ],
    short: "u",
    attached: "",
};
const CHECKOUT: Shape = Shape {
    long: &["--orphan", "--conflict", "--pathspec-from-file"],
    short: "bB",
    attached: "",
};
const SWITCH: Shape = Shape {
    long: &["--create", "--force-create", "--orphan", "--conflict"],
    short: "cC",
    attached: "",
};
const WORKTREE_ADD: Shape = Shape {
    long: &["--reason"],
    short: "bB",
    attached: "",
};
const REF: Shape = Shape {
    long: &[],
    short: "m",
    attached: "",
};
const PATHS: Shape = Shape {
    long: &["--pathspec-from-file", "--exclude"],
    short: "",
    attached: "",
};

/// The options and positionals of a subcommand's words.
#[derive(Default)]
struct Parsed<'a> {
    /// Short options seen without a value.
    shorts: String,
    /// Long options, without `=value`.
    longs: Vec<&'a str>,
    /// Option values, by option (`B`, `--force-create`).
    values: Vec<(String, Arg)>,
    positionals: Vec<&'a Arg>,
}

impl Parsed<'_> {
    fn has(&self, short: char) -> bool {
        self.shorts.contains(short)
    }

    fn long(&self, name: &str) -> bool {
        self.longs.contains(&name)
    }

    fn value(&self, opt: &str) -> Option<&Arg> {
        self.values.iter().find(|(o, _)| o == opt).map(|(_, v)| v)
    }
}

fn parse<'a>(shape: &Shape, words: &'a [Arg]) -> Parsed<'a> {
    let mut p = Parsed::default();
    let mut i = 0;
    while let Some(a) = words.get(i) {
        i += 1;
        let s = a.s.as_str();
        if s == "--" && !a.dynamic {
            p.positionals.extend(&words[i..]);
            break;
        }
        if let Some(long) = s.strip_prefix("--") {
            // `--opt=value`: the name is fixed text also when the value
            // is not.
            if let Some((name, value)) = long.split_once('=') {
                let name = &s[..name.len() + 2];
                p.longs.push(name);
                p.values.push((
                    name.to_owned(),
                    Arg {
                        s: value.to_owned(),
                        dynamic: a.dynamic,
                    },
                ));
            } else if a.dynamic {
                p.positionals.push(a);
            } else {
                p.longs.push(s);
                if shape.long.contains(&s) {
                    p.values
                        .extend(words.get(i).map(|v| (s.to_owned(), v.clone())));
                    i += 1;
                }
            }
            continue;
        }
        if !a.is_opt() || s.starts_with(super::cmds::DYNAMIC) {
            p.positionals.push(a);
            continue;
        }
        // A short cluster: flags, then at most one option with a value.
        for (k, c) in s.char_indices().skip(1) {
            let takes = shape.short.contains(c);
            if !takes && !shape.attached.contains(c) {
                if c != super::cmds::DYNAMIC {
                    p.shorts.push(c);
                }
                continue;
            }
            let glued = &s[k + c.len_utf8()..];
            if !glued.is_empty() {
                p.values.push((
                    c.to_string(),
                    Arg {
                        s: glued.to_owned(),
                        dynamic: a.dynamic,
                    },
                ));
            } else if takes {
                p.values
                    .extend(words.get(i).map(|v| (c.to_string(), v.clone())));
                i += 1;
            } else {
                p.shorts.push(c);
            }
            break;
        }
    }
    p
}

/// The rules for `git args...`.
#[must_use]
pub fn check(ctx: &Context, args: &[Arg]) -> Outcome {
    let mut out = Outcome {
        ruling: Ruling::Allow,
        waits: false,
        dirs: Vec::new(),
        writes: Vec::new(),
    };
    // Global options, up to the subcommand.
    let mut i = 0;
    let mut keys: Vec<&Arg> = Vec::new();
    while let Some(a) = args.get(i) {
        if a.dynamic && !a.s.starts_with("--config-env=") || !a.is_opt() {
            break;
        }
        i += 1;
        match a.s.as_str() {
            "-C" => {
                out.dirs.extend(args.get(i).cloned());
                i += 1;
            }
            "-c" | "--config-env" => {
                keys.extend(args.get(i));
                i += 1;
            }
            "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix" | "--attr-source" => {
                i += 1;
            }
            s => {
                if let Some(kv) = s.strip_prefix("--config-env=") {
                    out.ruling = out.ruling.max(config_override(kv));
                }
            }
        }
    }
    for k in keys {
        out.ruling = out.ruling.max(config_override(&k.s));
    }
    let Some(sub) = args.get(i) else {
        return out;
    };
    let rest = &args[i + 1..];
    let Some(sub) = sub.lit() else {
        // The subcommand is made at run time (ASK case 3).
        if rest.iter().any(|a| a.lit() == Some("--no-verify")) {
            out.ruling = out.ruling.max(Ruling::ask(
                "unclassified",
                "a git command whose subcommand is made at run time carries the hook-skip option (R26, case 3)",
            ));
        }
        return out;
    };
    out.waits = WAITING.contains(&sub);
    let ruling = subcommand(ctx, sub, rest, &mut out);
    out.ruling = out.ruling.max(ruling);
    out
}

/// M2a: a `-c` or `--config-env` pair whose key changes the hooks, or
/// the config or commands git runs.
fn config_override(pair: &str) -> Ruling {
    let key = pair.split('=').next().unwrap_or("").to_ascii_lowercase();
    if ["core.hooks", "include.", "includeif.", "alias."]
        .iter()
        .any(|p| key.starts_with(p))
    {
        return Ruling::deny(
            "git-c-hooks",
            format!(
                "`git -c {key}=...` changes the hooks or the config git reads for this command; run git without it (R25)"
            ),
        );
    }
    Ruling::Allow
}

fn subcommand(ctx: &Context, sub: &str, rest: &[Arg], out: &mut Outcome) -> Ruling {
    match sub {
        "commit" => hook_skip(sub, &parse(&COMMIT, rest), true),
        "am" => hook_skip(sub, &parse(&AM, rest), true),
        "merge" => hook_skip(sub, &parse(&MERGE, rest), false),
        "pull" => {
            let p = parse(&PULL, rest);
            hook_skip(sub, &p, false).max(local_transfer(ctx, sub, &p))
        }
        "push" => {
            let p = parse(&PUSH, rest);
            hook_skip(sub, &p, false).max(local_transfer(ctx, sub, &p))
        }
        "fetch" => local_transfer(ctx, sub, &parse(&FETCH, rest)),
        "branch" => branch(ctx, &parse(&BRANCH, rest)),
        "checkout" => create_over(ctx, "git checkout -B", parse(&CHECKOUT, rest).value("B")),
        "switch" => {
            let p = parse(&SWITCH, rest);
            create_over(
                ctx,
                "git switch -C",
                p.value("C").or_else(|| p.value("--force-create")),
            )
        }
        "worktree" if rest.first().and_then(Arg::lit) == Some("add") => create_over(
            ctx,
            "git worktree add -B",
            parse(&WORKTREE_ADD, &rest[1..]).value("B"),
        ),
        "update-ref" => {
            let p = parse(&REF, rest);
            match p.positionals.first().and_then(|a| a.lit()) {
                Some(r) if r.starts_with("refs/remotes/") => Ruling::deny(
                    "git-update-ref-remote",
                    format!(
                        "git update-ref writes the remote-tracking ref {r}, which the gate reads as the state of the remote (R25)"
                    ),
                ),
                Some(r) if r.starts_with("refs/heads/") && full(ctx, r) => {
                    full_ref_move("git update-ref", r)
                }
                _ => Ruling::Allow,
            }
        }
        "symbolic-ref" => {
            let p = parse(&REF, rest);
            let writes = p.positionals.len() >= 2 || p.has('d') || p.long("--delete");
            match p.positionals.first().and_then(|a| a.lit()) {
                Some(r)
                    if writes
                        && (r.starts_with("refs/remotes/")
                            || (r.starts_with("refs/heads/") && full(ctx, r))) =>
                {
                    Ruling::deny(
                        "git-symbolic-ref",
                        format!(
                            "git symbolic-ref rewrites {r} without a check; push through the gate (R25, R27)"
                        ),
                    )
                }
                _ => Ruling::Allow,
            }
        }
        "send-pack" | "receive-pack" => Ruling::deny(
            "git-pack-direct",
            format!("git {sub} moves refs without the pre-push hook; use git push (R25)"),
        ),
        "replace" => Ruling::deny(
            "git-replace",
            "git replace changes what a commit id reads as, under a record of the gate (R25)",
        ),
        "rm" | "mv" | "clean" => {
            let p = parse(&PATHS, rest);
            out.writes
                .extend(p.positionals.iter().map(|a| ((*a).clone(), true)));
            Ruling::Allow
        }
        "config" => config(rest, out),
        _ => Ruling::Allow,
    }
}

/// M1: the hook-skip option of `git commit`, `merge`, `pull`, `push` and
/// `am`. `-n` means it only for `commit` and `am` (`push -n` is a dry run,
/// `merge -n` and `pull -n` are `--no-stat`).
fn hook_skip(sub: &str, p: &Parsed<'_>, short_n: bool) -> Ruling {
    let word = if p.long("--no-verify") {
        "--no-verify"
    } else if short_n && p.has('n') {
        "-n"
    } else {
        return Ruling::Allow;
    };
    Ruling::deny(
        "no-verify",
        format!(
            "git {sub} {word} skips the gate hooks; run it without {word} and fix what the check reports (R25)"
        ),
    )
}

/// True when `name` (`main` or `refs/heads/main`) is a full ref (R27).
fn full(ctx: &Context, name: &str) -> bool {
    let n = name.strip_prefix("refs/heads/").unwrap_or(name);
    !n.is_empty() && ctx.full_refs.is_match(n)
}

fn full_ref_move(how: &str, name: &str) -> Ruling {
    Ruling::deny(
        "full-ref-move",
        format!(
            "{how} moves the full ref {name} without a check; merge with `tollgate merge` or push through the gate (R25, R27)"
        ),
    )
}

/// M5a, M5c: `git branch` with `-f`, `-m`, `-M`, `-c`, `-C`.
fn branch(ctx: &Context, p: &Parsed<'_>) -> Ruling {
    let moves =
        ['m', 'M', 'c', 'C'].iter().any(|c| p.has(*c)) || p.long("--move") || p.long("--copy");
    let named = |a: &&Arg| a.lit().filter(|n| full(ctx, n)).map(str::to_owned);
    if moves {
        if let Some(n) = p.positionals.iter().find_map(named) {
            return Ruling::deny(
                "branch-move-full",
                format!(
                    "git branch renames or copies over the full ref {n} without a check (R25, R27)"
                ),
            );
        }
        return Ruling::ask(
            "branch-move",
            "git branch -m/-c renames or copies a branch: records of the gate stay with the old name (R26)",
        );
    }
    if (p.has('f') || p.long("--force"))
        && let Some(n) = p.positionals.first().and_then(named)
    {
        return Ruling::deny(
            "branch-move-full",
            format!(
                "git branch -f moves the full ref {n} without a check; merge with `tollgate merge` (R25, R27)"
            ),
        );
    }
    Ruling::Allow
}

/// M5a: `checkout -B`, `switch -C`, `worktree add -B` with a full ref.
fn create_over(ctx: &Context, how: &str, name: Option<&Arg>) -> Ruling {
    match name.and_then(Arg::lit) {
        Some(n) if full(ctx, n) => Ruling::deny(
            "branch-move-full",
            format!(
                "{how} resets the full ref {n} without a check; merge with `tollgate merge` (R25, R27)"
            ),
        ),
        _ => Ruling::Allow,
    }
}

/// M5a: `git push . src:dst`, `git fetch . src:dst` and `git pull .
/// src:dst` write a ref of this repo with no hook.
fn local_transfer(ctx: &Context, sub: &str, p: &Parsed<'_>) -> Ruling {
    let mut words = p.positionals.iter();
    if words.next().and_then(|a| a.lit()) != Some(".") {
        return Ruling::Allow;
    }
    for spec in words.filter_map(|a| a.lit()) {
        let Some((_, dst)) = spec.trim_start_matches('+').split_once(':') else {
            continue;
        };
        if dst.starts_with("refs/remotes/") || full(ctx, dst) {
            return full_ref_move(&format!("git {sub} ."), dst);
        }
    }
    Ruling::Allow
}

/// M2d: a `git config` call that writes a key which changes the hooks,
/// the config git reads, the commands it runs or the server it reaches.
fn config(rest: &[Arg], out: &mut Outcome) -> Ruling {
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
    const WITH_VALUE: &[&str] = &["--blob", "--type", "--default", "--comment", "--value"];
    let mut positionals: Vec<&Arg> = Vec::new();
    let (mut write, mut read, mut edit) = (false, false, false);
    let mut file: Option<Arg> = None;
    let mut i = 0;
    while let Some(a) = rest.get(i) {
        i += 1;
        let s = a.s.as_str();
        if a.dynamic && !s.starts_with("--file=") {
            positionals.push(a);
        } else if s == "--file" || s == "-f" {
            file = rest.get(i).cloned();
            i += 1;
        } else if let Some(f) = s.strip_prefix("--file=") {
            file = Some(Arg {
                s: f.to_owned(),
                dynamic: a.dynamic,
            });
        } else if WITH_VALUE.contains(&s) {
            i += 1;
        } else if WRITE_FLAGS.contains(&s) {
            write = true;
            edit |= s == "--edit" || s == "-e";
        } else if READ_FLAGS.contains(&s) {
            read = true;
        } else if positionals.is_empty() && WRITE_SUBS.contains(&s) {
            write = true;
            edit |= s == "edit";
        } else if !a.is_opt() {
            positionals.push(a);
        }
    }
    if !(write || (!read && positionals.len() >= 2)) {
        return Ruling::Allow;
    }
    out.writes.extend(file.map(|f| (f, false)));
    if edit {
        return Ruling::ask(
            "git-config-write",
            "git config --edit opens a config file for any change (R26)",
        );
    }
    let key = positionals
        .first()
        .and_then(|a| a.lit())
        .unwrap_or("")
        .to_ascii_lowercase();
    let guarded = ["include", "alias.", "url.", "ssh."]
        .iter()
        .any(|p| key.starts_with(p))
        || matches!(
            key.as_str(),
            "core.hookspath" | "core.sshcommand" | "core.gitproxy"
        );
    if guarded {
        return Ruling::ask(
            "git-config-write",
            format!(
                "git config writes {}, which changes the hooks, the config or the server git uses (R26)",
                positionals[0].s
            ),
        );
    }
    Ruling::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<Arg> {
        s.split(' ').map(Arg::fixed).collect()
    }

    #[test]
    fn option_values_are_never_options_or_positionals() {
        let a = args("-am msg -n");
        let p = parse(&COMMIT, &a);
        assert_eq!(p.shorts, "an");
        assert_eq!(p.value("m").unwrap().s, "msg");
        let a = args("-mfoo -Snone -uno --author=n --date now x -- -n");
        let p = parse(&COMMIT, &a);
        assert_eq!(p.shorts, "");
        assert_eq!(p.value("--author").unwrap().s, "n");
        assert_eq!(
            p.positionals
                .iter()
                .map(|a| a.s.as_str())
                .collect::<Vec<_>>(),
            ["x", "-n"]
        );
        let a = args("-qBmain");
        assert_eq!(parse(&CHECKOUT, &a).value("B").unwrap().s, "main");
        let a = args("-S -n");
        assert_eq!(parse(&COMMIT, &a).shorts, "Sn");
    }
}
