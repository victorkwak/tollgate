//! The options of the git subcommands that create, reset, rename or copy a
//! branch (`checkout`, `switch`, `worktree add`, `branch`), read the way
//! git's parse-options reads them (G7, item 22, secreview note 5).
//!
//! git takes short options in groups (`-fC`), a value glued to its letter
//! (`-Bmain`) or in the next word, and a long option abbreviated to any
//! prefix that names one option (`--force-c`, `--forc`). An abbreviation
//! that names several options is an error in git. Here a prefix of an
//! option that writes a branch counts as that option even where git finds
//! it ambiguous: git then refuses the command, so the guard loses nothing,
//! and a table that is short of an option git has never hides one.
//!
//! The tables follow `git <sub> -h` of git 2.56.

/// A subcommand's option table.
pub(super) struct Table {
    /// Long options that take a value: after `=`, or the next word.
    long_val: &'static [&'static str],
    /// The other long options (a value only after `=`).
    long_flag: &'static [&'static str],
    /// Short letters that take a value: the rest of the group, or the next
    /// word.
    short_val: &'static str,
    /// Long options that write a branch.
    write_long: &'static [&'static str],
}

pub(super) const CHECKOUT: Table = Table {
    long_val: &[
        "conflict",
        "orphan",
        "unified",
        "inter-hunk-context",
        "pathspec-from-file",
    ],
    long_flag: &[
        "guess",
        "overlay",
        "auto-advance",
        "quiet",
        "recurse-submodules",
        "progress",
        "merge",
        "detach",
        "track",
        "force",
        "overwrite-ignore",
        "ignore-other-worktrees",
        "ours",
        "theirs",
        "patch",
        "ignore-skip-worktree-bits",
        "pathspec-file-nul",
    ],
    short_val: "bBU",
    write_long: &[],
};

pub(super) const SWITCH: Table = Table {
    long_val: &["create", "force-create", "conflict", "orphan"],
    long_flag: &[
        "guess",
        "discard-changes",
        "quiet",
        "recurse-submodules",
        "progress",
        "merge",
        "detach",
        "track",
        "force",
        "overwrite-ignore",
        "ignore-other-worktrees",
    ],
    short_val: "cC",
    write_long: &["force-create"],
};

pub(super) const WORKTREE_ADD: Table = Table {
    long_val: &["reason"],
    long_flag: &[
        "force",
        "orphan",
        "detach",
        "checkout",
        "lock",
        "quiet",
        "track",
        "guess-remote",
        "relative-paths",
    ],
    short_val: "bB",
    write_long: &[],
};

pub(super) const BRANCH: Table = Table {
    long_val: &[
        "set-upstream-to",
        "contains",
        "no-contains",
        "delete-merged",
        "merged",
        "no-merged",
        "forked",
        "sort",
        "points-at",
        "format",
    ],
    long_flag: &[
        "verbose",
        "quiet",
        "track",
        "unset-upstream",
        "color",
        "remotes",
        "abbrev",
        "all",
        "delete",
        "move",
        "omit-empty",
        "copy",
        "list",
        "show-current",
        "create-reflog",
        "edit-description",
        "dry-run",
        "force",
        "column",
        "ignore-case",
        "recurse-submodules",
    ],
    short_val: "u",
    write_long: &["force", "move", "copy"],
};

/// `git push` (item 22, secreview note 7): which word is the repository
/// and which are refspecs. `--repo`, `--all`, `--branches` and `--mirror`
/// pick what is pushed.
pub(super) const PUSH: Table = Table {
    long_val: &[
        "repo",
        "recurse-submodules",
        "receive-pack",
        "exec",
        "push-option",
    ],
    long_flag: &[
        "verbose",
        "quiet",
        "all",
        "branches",
        "mirror",
        "delete",
        "tags",
        "dry-run",
        "porcelain",
        "force",
        "force-with-lease",
        "force-if-includes",
        "thin",
        "set-upstream",
        "progress",
        "prune",
        "verify",
        "follow-tags",
        "signed",
        "atomic",
        "ipv4",
        "ipv6",
    ],
    short_val: "o",
    write_long: &["repo", "all", "branches", "mirror"],
};

/// `git fetch` (item 22, secreview note 7), with its hidden options
/// `--submodule-prefix` and `--recurse-submodules-default`.
pub(super) const FETCH: Table = Table {
    long_val: &[
        "upload-pack",
        "jobs",
        "depth",
        "shallow-since",
        "shallow-exclude",
        "deepen",
        "refmap",
        "server-option",
        "negotiation-restrict",
        "negotiation-tip",
        "negotiation-include",
        "filter",
        "submodule-prefix",
        "recurse-submodules-default",
    ],
    long_flag: &[
        "verbose",
        "quiet",
        "all",
        "set-upstream",
        "append",
        "atomic",
        "force",
        "multiple",
        "tags",
        "prefetch",
        "prune",
        "prune-tags",
        "recurse-submodules",
        "dry-run",
        "porcelain",
        "write-fetch-head",
        "keep",
        "update-head-ok",
        "progress",
        "unshallow",
        "refetch",
        "update-shallow",
        "ipv4",
        "ipv6",
        "negotiate-only",
        "auto-maintenance",
        "auto-gc",
        "show-forced-updates",
        "write-commit-graph",
        "stdin",
    ],
    short_val: "jo",
    write_long: &["refmap", "stdin"],
};

/// `git pull` (item 22, secreview note 7): its refspecs are fetch
/// refspecs.
pub(super) const PULL: Table = Table {
    long_val: &[
        "cleanup",
        "strategy",
        "strategy-option",
        "upload-pack",
        "depth",
        "shallow-since",
        "shallow-exclude",
        "deepen",
        "refmap",
        "server-option",
        "negotiation-restrict",
        "negotiation-tip",
        "negotiation-include",
    ],
    long_flag: &[
        "verbose",
        "quiet",
        "progress",
        "recurse-submodules",
        "rebase",
        "stat",
        "compact-summary",
        "log",
        "signoff",
        "squash",
        "commit",
        "edit",
        "ff",
        "ff-only",
        "verify",
        "verify-signatures",
        "autostash",
        "gpg-sign",
        "allow-unrelated-histories",
        "all",
        "append",
        "force",
        "tags",
        "prune",
        "jobs",
        "dry-run",
        "keep",
        "unshallow",
        "update-shallow",
        "ipv4",
        "ipv6",
        "show-forced-updates",
        "set-upstream",
    ],
    short_val: "sXo",
    write_long: &["refmap"],
};

/// A word as the guard sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Arg {
    Known(String),
    /// A word bash builds at run time. `split`: bash can make several
    /// words of it (an unquoted expansion or a brace). `dash`: its first
    /// character is not fixed text other than `-`, so it can be an option.
    Unknown {
        raw: String,
        split: bool,
        dash: bool,
    },
}

/// An option as git reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Opt {
    /// `-X` for a short letter, `--name` for a long option (the full name
    /// git resolves it to; a prefix of an option that writes a branch is
    /// that option).
    pub key: String,
    /// The option as written.
    pub written: String,
    /// The value, when the option takes one. `None`: no value, or no word
    /// left for it (git refuses the command).
    pub value: Option<Arg>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Parsed {
    pub opts: Vec<Opt>,
    /// The words that are not options or values.
    pub positionals: Vec<Arg>,
    /// The first long option the table cannot name with certainty (not in
    /// the table, or a prefix of several): whether git takes the next word
    /// as its value is not known, so the next word was read as an option.
    pub uncertain: Option<String>,
}

enum Long {
    /// A long option of the table, with a value word or not.
    Val(&'static str),
    Flag(&'static str),
    /// `--no-<name>`: never a value word.
    Neg,
    Unknown,
}

fn resolve_long(t: &Table, name: &str) -> Long {
    let exact_val = t.long_val.iter().find(|n| **n == name);
    let exact_flag = t.long_flag.iter().find(|n| **n == name);
    if let Some(n) = exact_val {
        return Long::Val(n);
    }
    if let Some(n) = exact_flag {
        return Long::Flag(n);
    }
    let all = || t.long_val.iter().chain(t.long_flag);
    if let Some(rest) = name.strip_prefix("no-")
        && all().any(|n| *n == rest)
    {
        return Long::Neg;
    }
    // Not an exact name: a prefix of an option that writes a branch is
    // that option (fail closed: git refuses an ambiguous prefix).
    if !name.is_empty()
        && let Some(w) = t.write_long.iter().find(|w| w.starts_with(name))
    {
        return if t.long_val.contains(w) {
            Long::Val(w)
        } else {
            Long::Flag(w)
        };
    }
    let mut hits = all()
        .filter(|n| n.starts_with(name))
        .map(|n| {
            if t.long_val.contains(n) {
                Long::Val(n)
            } else {
                Long::Flag(n)
            }
        })
        .chain(
            // `--no-contains` is an option of its own, not a negation.
            all()
                .map(|n| format!("no-{n}"))
                .filter(|neg| neg.starts_with(name) && !all().any(|n| n == neg))
                .map(|_| Long::Neg),
        );
    match (hits.next(), hits.next()) {
        (Some(one), None) if !name.is_empty() => one,
        _ => Long::Unknown,
    }
}

/// Reads `args` (the words after the subcommand) as git does. A word bash
/// builds at run time where git can read an option is an error, and so is
/// one that bash can split into several words before `--`.
pub(super) fn parse(t: &Table, args: &[Arg]) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    let mut i = 0;
    let next = |i: &mut usize| -> Result<Option<Arg>, String> {
        let v = args.get(*i).cloned();
        *i += 1;
        if let Some(Arg::Unknown {
            raw, split: true, ..
        }) = &v
        {
            return Err(format!(
                "`{raw}`, a word bash builds at run time and can split into several words"
            ));
        }
        Ok(v)
    };
    while i < args.len() {
        let a = match &args[i] {
            Arg::Known(a) => a.clone(),
            Arg::Unknown { raw, split, dash } => {
                if *split || *dash {
                    return Err(format!(
                        "`{raw}`, a word bash builds at run time where git reads options; put --end-of-options before it"
                    ));
                }
                out.positionals.push(args[i].clone());
                i += 1;
                continue;
            }
        };
        i += 1;
        if a == "--" || a == "--end-of-options" {
            out.positionals.extend(args[i..].iter().cloned());
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((n, v)) => (n, Some(Arg::Known(v.to_owned()))),
                None => (long, None),
            };
            let (key, takes) = match resolve_long(t, name) {
                Long::Val(n) => (format!("--{n}"), true),
                Long::Flag(n) => (format!("--{n}"), false),
                Long::Neg => (format!("--{name}"), false),
                Long::Unknown => {
                    out.uncertain.get_or_insert_with(|| a.clone());
                    (format!("--{name}"), false)
                }
            };
            let value = match glued {
                Some(v) => Some(v),
                None if takes => next(&mut i)?,
                None => None,
            };
            out.opts.push(Opt {
                key,
                written: a.clone(),
                value,
            });
            continue;
        }
        if let Some(group) = a.strip_prefix('-').filter(|g| !g.is_empty()) {
            for (k, c) in group.char_indices() {
                let rest = &group[k + c.len_utf8()..];
                if t.short_val.contains(c) {
                    let value = if rest.is_empty() {
                        next(&mut i)?
                    } else {
                        Some(Arg::Known(rest.to_owned()))
                    };
                    out.opts.push(Opt {
                        key: format!("-{c}"),
                        written: a.clone(),
                        value,
                    });
                    break;
                }
                out.opts.push(Opt {
                    key: format!("-{c}"),
                    written: a.clone(),
                    value: None,
                });
            }
            continue;
        }
        out.positionals.push(Arg::Known(a));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known(words: &[&str]) -> Vec<Arg> {
        words.iter().map(|w| Arg::Known((*w).to_owned())).collect()
    }

    fn opts(t: &Table, words: &[&str]) -> Vec<(String, Option<String>)> {
        parse(t, &known(words))
            .unwrap()
            .opts
            .into_iter()
            .map(|o| {
                let v = o.value.map(|v| match v {
                    Arg::Known(s) => s,
                    Arg::Unknown { raw, .. } => raw,
                });
                (o.key, v)
            })
            .collect()
    }

    fn o(k: &str, v: Option<&str>) -> (String, Option<String>) {
        (k.to_owned(), v.map(str::to_owned))
    }

    #[test]
    fn groups_glued_values_and_prefixes() {
        assert_eq!(
            opts(&SWITCH, &["-fC", "main", "x"]),
            [o("-f", None), o("-C", Some("main"))]
        );
        assert_eq!(
            opts(&CHECKOUT, &["-qfBmain"]),
            [o("-q", None), o("-f", None), o("-B", Some("main"))]
        );
        // A letter with a value hides the letters after it.
        assert_eq!(opts(&CHECKOUT, &["-bBx"]), [o("-b", Some("Bx"))]);
        assert_eq!(opts(&CHECKOUT, &["-U3"]), [o("-U", Some("3"))]);
        // Exact names win; a prefix of a writing option is that option.
        assert_eq!(opts(&SWITCH, &["--force"]), [o("--force", None)]);
        assert_eq!(
            opts(&SWITCH, &["--force-c", "main"]),
            [o("--force-create", Some("main"))]
        );
        assert_eq!(
            opts(&SWITCH, &["--forc", "main"]),
            [o("--force-create", Some("main"))]
        );
        assert_eq!(
            opts(&SWITCH, &["--no-force-c", "main"]),
            [o("--no-force-c", None)]
        );
        assert_eq!(opts(&BRANCH, &["--forc"]), [o("--force", None)]);
        assert_eq!(opts(&BRANCH, &["--mo"]), [o("--move", None)]);
        assert_eq!(
            opts(&BRANCH, &["--sor", "refname"]),
            [o("--sort", Some("refname"))]
        );
        assert_eq!(
            opts(&BRANCH, &["--no-con", "x"]),
            [o("--no-contains", Some("x"))]
        );
        assert_eq!(
            opts(&WORKTREE_ADD, &["--reason", "-B"]),
            [o("--reason", Some("-B"))]
        );
    }

    #[test]
    fn positionals_and_end_of_options() {
        let p = parse(&BRANCH, &known(&["-f", "--", "-x", "main"])).unwrap();
        assert_eq!(p.positionals, known(&["-x", "main"]));
        let p = parse(&CHECKOUT, &known(&["--end-of-options", "-Bmain"])).unwrap();
        assert!(p.opts.is_empty());
        let p = parse(&BRANCH, &known(&["--bogus", "x", "y"])).unwrap();
        assert_eq!(p.uncertain.as_deref(), Some("--bogus"));
        assert_eq!(p.positionals, known(&["x", "y"]));
    }

    #[test]
    fn words_bash_builds() {
        let u = |raw: &str, split, dash| Arg::Unknown {
            raw: raw.into(),
            split,
            dash,
        };
        // One word that cannot start with `-`: a positional.
        assert!(parse(&CHECKOUT, &[u("feat/$N", false, false)]).is_ok());
        // Can be an option, or can split: refused.
        assert!(parse(&CHECKOUT, &[u("\"$B\"", false, true)]).is_err());
        assert!(parse(&CHECKOUT, &[u("x$B", true, false)]).is_err());
        // A value can be anything, unless bash splits it.
        let mut w = known(&["-b"]);
        w.push(u("\"$B\"", false, true));
        assert!(parse(&CHECKOUT, &w).is_ok());
        let mut w = known(&["-b"]);
        w.push(u("$B", true, true));
        assert!(parse(&CHECKOUT, &w).is_err());
        // After --, words are not options.
        let mut w = known(&["--"]);
        w.push(u("$B", true, true));
        assert!(parse(&CHECKOUT, &w).is_ok());
    }
}
