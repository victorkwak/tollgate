//! Tables of the programs the walker knows by name: shells, plain
//! wrappers, and the ordinary tools that write the files they name (M3).
//! A program that is not in a table is unknown: its arguments are data.

/// One word of a command after expansion: its text, and whether a part
/// of it is only known at run time (that part is `\u{1}` in the text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg {
    pub s: String,
    pub dynamic: bool,
}

impl Arg {
    #[must_use]
    pub fn fixed(s: impl Into<String>) -> Self {
        Self {
            s: s.into(),
            dynamic: false,
        }
    }

    /// The word, when all of it is known.
    #[must_use]
    pub fn lit(&self) -> Option<&str> {
        (!self.dynamic).then_some(self.s.as_str())
    }

    /// True for a word bash and the program read as an option.
    #[must_use]
    pub fn is_opt(&self) -> bool {
        self.s.len() > 1 && self.s.starts_with('-')
    }
}

/// The mark a run-time part leaves in [`Arg::s`].
pub const DYNAMIC: char = '\u{1}';

/// The shells whose `-c` text, stdin and script files the walker reads.
#[must_use]
pub fn is_shell(name: &str) -> bool {
    matches!(name, "sh" | "bash" | "zsh" | "dash")
}

/// Programs whose arguments are text or patterns and never a command:
/// ASK case 5 does not read their words.
#[must_use]
pub fn takes_text(name: &str) -> bool {
    matches!(
        name,
        "echo" | "printf" | "grep" | "egrep" | "fgrep" | "rg" | "sed" | "awk" | "gawk" | "jq"
    )
}

/// A plain wrapper: it runs the command in its arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wrapper {
    Env,
    Command,
    Exec,
    Sudo,
    Timeout,
    Xargs,
    Find,
    /// `time`, `nice`, `nohup`: options, then the command.
    Plain(&'static [&'static str]),
}

#[must_use]
pub fn wrapper(name: &str) -> Option<Wrapper> {
    Some(match name {
        "env" => Wrapper::Env,
        "command" => Wrapper::Command,
        "exec" => Wrapper::Exec,
        "sudo" => Wrapper::Sudo,
        "timeout" => Wrapper::Timeout,
        "xargs" => Wrapper::Xargs,
        "find" => Wrapper::Find,
        "time" | "nohup" => Wrapper::Plain(&[]),
        "nice" => Wrapper::Plain(&["-n", "--adjustment"]),
        _ => return None,
    })
}

/// Options of `sudo`, `timeout` and `xargs` that take the next word.
pub const SUDO_VALUED: &[&str] = &[
    "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "-D", "--chdir", "-r",
    "-t", "-T", "-U",
];
pub const TIMEOUT_VALUED: &[&str] = &["-s", "--signal", "-k", "--kill-after"];
pub const XARGS_VALUED: &[&str] = &[
    "-I",
    "-n",
    "-P",
    "-L",
    "-d",
    "-s",
    "-a",
    "-E",
    "--max-args",
    "--max-procs",
    "--max-lines",
    "--delimiter",
    "--arg-file",
    "--replace",
];

/// The index of the first word of `args` that is not an option or the
/// value of an option in `valued`. `--` ends the options.
#[must_use]
pub fn operands_at(args: &[Arg], valued: &[&str]) -> usize {
    let mut i = 0;
    while let Some(a) = args.get(i) {
        if a.dynamic || !a.is_opt() {
            break;
        }
        i += 1;
        if a.s == "--" {
            break;
        }
        if valued.contains(&a.s.as_str()) {
            i += 1;
        }
    }
    i
}

/// Which operands an ordinary tool writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pick {
    /// Every operand.
    All,
    /// Every operand, and the tool removes them (`rm`, `rmdir`).
    Removed,
    /// `mv`: the sources go away, the last operand is written.
    Moved,
    /// The last of two or more operands (`cp`, `ln`, `install`, `rsync`).
    Last,
    /// Every operand after the first (`chmod MODE`, `chown OWNER`); `-R`
    /// reaches what is under them.
    Rest,
    /// `sed -i`: the files after the script.
    Sed,
    /// `perl -i`: the files after the code.
    Perl,
    /// `dd of=FILE`.
    Dd,
}

/// The writer table (M3): name, how it picks its targets, and the options
/// that take the next word.
const WRITERS: &[(&str, Pick, &[&str])] = &[
    ("rm", Pick::Removed, &[]),
    ("rmdir", Pick::Removed, &[]),
    ("mv", Pick::Moved, &["-S", "--suffix"]),
    ("cp", Pick::Last, &["-S", "--suffix"]),
    ("ln", Pick::Last, &["-S", "--suffix"]),
    (
        "install",
        Pick::Last,
        &["-m", "--mode", "-o", "--owner", "-g", "--group", "-S"],
    ),
    (
        "rsync",
        Pick::Last,
        &["-e", "--rsh", "-f", "--filter", "--exclude", "--include"],
    ),
    ("tee", Pick::All, &[]),
    ("unlink", Pick::Removed, &[]),
    (
        "touch",
        Pick::All,
        &["-d", "--date", "-r", "--reference", "-t"],
    ),
    (
        "truncate",
        Pick::All,
        &["-s", "--size", "-r", "--reference"],
    ),
    ("chmod", Pick::Rest, &[]),
    ("chown", Pick::Rest, &[]),
    (
        "sed",
        Pick::Sed,
        &["-e", "--expression", "-f", "--file", "-l"],
    ),
    ("perl", Pick::Perl, &["-I"]),
    ("dd", Pick::Dd, &[]),
];

/// The words of `name args...` that the tool writes, each with "the tool
/// removes it, or reaches what is under it"; `None` when `name` is not in
/// the writer table.
#[must_use]
pub fn write_targets(name: &str, args: &[Arg]) -> Option<Vec<(Arg, bool)>> {
    let (_, pick, valued) = WRITERS.iter().find(|(n, ..)| *n == name)?;
    let mut ops: Vec<&Arg> = Vec::new();
    let mut out: Vec<(Arg, bool)> = Vec::new();
    // sed and perl: the option that edits in place, and the one that
    // carries the script.
    let (mut in_place, mut script_opt, mut recursive) = (false, false, false);
    let mut i = 0;
    let mut opts = true;
    while let Some(a) = args.get(i) {
        i += 1;
        if !opts || a.dynamic || !a.is_opt() {
            ops.push(a);
            continue;
        }
        let s = a.s.as_str();
        // `chmod -x FILE`: a mode, not an option.
        if name == "chmod" && s[1..].chars().all(|c| "rwxXstugo".contains(c)) {
            ops.push(a);
            continue;
        }
        if s == "--" {
            opts = false;
        } else if s == "-t" || s == "--target-directory" {
            if *pick == Pick::Last || *pick == Pick::Moved {
                out.extend(args.get(i).map(|t| (t.clone(), false)));
            }
            i += 1;
        } else if let Some(t) = s.strip_prefix("--target-directory=") {
            out.push((Arg::fixed(t), false));
        } else if valued.contains(&s) {
            script_opt |= matches!(s, "-e" | "--expression" | "-f" | "--file");
            i += 1;
        } else if s.starts_with("--") {
            in_place |= s.starts_with("--in-place");
            recursive |= s == "--recursive";
            script_opt |= s.starts_with("--expression=") || s.starts_with("--file=");
        } else {
            // A short cluster: `-ni`, `-i.bak`, `-pi`, `-pie CODE`, `-R`.
            let letters = &s[1..];
            let before_i = letters.split('i').next().unwrap_or("");
            in_place |=
                letters.contains('i') && before_i.chars().all(|c| "pnlwsa0Eruz".contains(c));
            recursive |= letters.contains('R');
            let code = if *pick == Pick::Perl {
                letters.ends_with(['e', 'E'])
            } else {
                *pick == Pick::Sed && letters.ends_with(['e', 'f'])
            };
            if code {
                script_opt = true;
                i += 1;
            }
        }
    }
    let own = |a: &&Arg, removal: bool| ((*a).clone(), removal);
    match pick {
        Pick::All => out.extend(ops.iter().map(|a| own(a, false))),
        Pick::Removed => out.extend(ops.iter().map(|a| own(a, true))),
        Pick::Moved => {
            let n = ops.len();
            let sources = if out.is_empty() {
                n.saturating_sub(1)
            } else {
                n
            };
            out.extend(ops.iter().enumerate().map(|(k, a)| own(a, k < sources)));
        }
        Pick::Last => {
            if out.is_empty() && ops.len() >= 2 {
                out.extend(ops.last().map(|a| own(a, false)));
            }
        }
        Pick::Rest => out.extend(ops.iter().skip(1).map(|a| own(a, recursive))),
        Pick::Sed | Pick::Perl => {
            if in_place {
                let skip = usize::from(!script_opt);
                out.extend(ops.iter().skip(skip).map(|a| own(a, false)));
            }
        }
        Pick::Dd => out.extend(ops.iter().filter_map(|a| {
            let file = a.s.strip_prefix("of=")?;
            Some((
                Arg {
                    s: file.to_owned(),
                    dynamic: a.dynamic,
                },
                false,
            ))
        })),
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(cmd: &str) -> Vec<(String, bool)> {
        let words: Vec<Arg> = cmd.split(' ').map(Arg::fixed).collect();
        write_targets(&words[0].s, &words[1..])
            .unwrap()
            .into_iter()
            .map(|(a, r)| (a.s, r))
            .collect()
    }

    #[test]
    fn the_writer_table_picks_the_written_words() {
        let t = |v: &[(&str, bool)]| -> Vec<(String, bool)> {
            v.iter().map(|(s, r)| ((*s).to_owned(), *r)).collect()
        };
        assert_eq!(targets("rm -rf a b"), t(&[("a", true), ("b", true)]));
        assert_eq!(
            targets("mv a b c"),
            t(&[("a", true), ("b", true), ("c", false)])
        );
        assert_eq!(targets("mv -t d a"), t(&[("d", false), ("a", true)]));
        assert_eq!(targets("cp -r a b"), t(&[("b", false)]));
        assert_eq!(targets("cp a"), t(&[]));
        assert_eq!(targets("ln -sf a b"), t(&[("b", false)]));
        assert_eq!(targets("install -m 755 a b"), t(&[("b", false)]));
        assert_eq!(targets("tee -a a b"), t(&[("a", false), ("b", false)]));
        assert_eq!(targets("chmod -R 700 a"), t(&[("a", true)]));
        assert_eq!(targets("chown u:g a"), t(&[("a", false)]));
        assert_eq!(targets("truncate -s 0 a"), t(&[("a", false)]));
        assert_eq!(targets("dd if=a of=b"), t(&[("b", false)]));
        // sed and perl write only with the in-place option.
        assert_eq!(targets("sed -n 1,2p a"), t(&[]));
        assert_eq!(targets("sed -i s/a/b/ a"), t(&[("a", false)]));
        assert_eq!(targets("sed -i.bak -e s/a/b/ a"), t(&[("a", false)]));
        assert_eq!(
            targets("sed -ni -e p a b"),
            t(&[("a", false), ("b", false)])
        );
        assert_eq!(targets("sed --in-place=.b s/a/b/ a"), t(&[("a", false)]));
        assert_eq!(targets("sed -Ei s/a/b/ a"), t(&[("a", false)]));
        assert_eq!(targets("perl -Mstrict -e 1 a"), t(&[]));
        assert_eq!(targets("cp --target-directory=d a"), t(&[("d", false)]));
        assert_eq!(targets("perl -ne print a"), t(&[]));
        assert_eq!(targets("perl -pi -e s/a/b/ a"), t(&[("a", false)]));
        assert_eq!(targets("perl -pie s/a/b/ a"), t(&[("a", false)]));
        assert_eq!(targets("perl -i.bak -pe s/a/b/ a"), t(&[("a", false)]));
        assert!(write_targets("cat", &[]).is_none());
    }

    #[test]
    fn operands_start_after_the_options_and_their_values() {
        let words: Vec<Arg> = "-k 5 --foreground 10 make"
            .split(' ')
            .map(Arg::fixed)
            .collect();
        assert_eq!(operands_at(&words, TIMEOUT_VALUED), 3);
        let words: Vec<Arg> = "-- -x".split(' ').map(Arg::fixed).collect();
        assert_eq!(operands_at(&words, &[]), 1);
    }
}
