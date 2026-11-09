//! Text the guard reads as data, not as something that runs (R25).
//!
//! - Item 42: a literal message of `git commit`, `git merge` or `git tag`
//!   (`-m`, `--message`, a quoted heredoc on `-F -`) is text git stores.
//!   The substring rules skip it, so a message can name `--no-verify` or
//!   `GIT_CONFIG_COUNT`. Options are read in git's order. It stays text
//!   git stores only while git runs no editor on it, so an edit option or
//!   an option this table does not know (it can be an abbreviated
//!   `--edit`) leaves the whole command checked as before.
//!
//! Item 51 (exact data exemptions, "runs git" read from the parsed command
//! words, an interpreter's program text as code) is in [`super::rules`];
//! the deny list of what python text can do is gone (security review
//! notes of 2026-11-09).

/// The options of a git subcommand that carries a message (git 2.56).
struct Options {
    /// Short options without a value.
    flags: &'static str,
    /// Short options whose value is the rest of the word or the next word.
    valued: &'static str,
    /// Short options whose optional value is only the rest of the word.
    glued: &'static str,
    /// Long options with a value (`--x v` or `--x=v`); `--no-x` has none
    /// unless it is listed here too.
    long_valued: &'static [&'static str],
    /// Long options without a value (or with one only after `=`).
    long_flags: &'static [&'static str],
}

const COMMIT: Options = Options {
    flags: "qvseaiponz",
    valued: "mFcCtU",
    glued: "Su",
    long_valued: &[
        "--file",
        "--author",
        "--date",
        "--message",
        "--reedit-message",
        "--reuse-message",
        "--fixup",
        "--squash",
        "--trailer",
        "--template",
        "--cleanup",
        "--unified",
        "--inter-hunk-context",
        "--pathspec-from-file",
    ],
    long_flags: &[
        "--quiet",
        "--verbose",
        "--reset-author",
        "--signoff",
        "--edit",
        "--status",
        "--gpg-sign",
        "--all",
        "--include",
        "--interactive",
        "--patch",
        "--only",
        "--verify",
        "--dry-run",
        "--short",
        "--branch",
        "--ahead-behind",
        "--porcelain",
        "--long",
        "--null",
        "--amend",
        "--post-rewrite",
        "--untracked-files",
        "--pathspec-file-nul",
        "--allow-empty",
        "--allow-empty-message",
    ],
};

const MERGE: Options = Options {
    flags: "nevq",
    valued: "sXmF",
    glued: "S",
    long_valued: &[
        "--cleanup",
        "--strategy",
        "--strategy-option",
        "--message",
        "--file",
        "--into-name",
    ],
    long_flags: &[
        "--stat",
        "--summary",
        "--compact-summary",
        "--log",
        "--squash",
        "--commit",
        "--edit",
        "--ff",
        "--ff-only",
        "--rerere-autoupdate",
        "--verify-signatures",
        "--verbose",
        "--quiet",
        "--abort",
        "--quit",
        "--continue",
        "--allow-unrelated-histories",
        "--progress",
        "--gpg-sign",
        "--autostash",
        "--overwrite-ignore",
        "--signoff",
        "--verify",
    ],
};

const TAG: Options = Options {
    flags: "ldvaesfi",
    valued: "mFu",
    glued: "n",
    long_valued: &[
        "--message",
        "--file",
        "--trailer",
        "--cleanup",
        "--local-user",
        "--contains",
        "--no-contains",
        "--merged",
        "--no-merged",
        "--sort",
        "--points-at",
        "--format",
    ],
    long_flags: &[
        "--list",
        "--delete",
        "--verify",
        "--annotate",
        "--edit",
        "--sign",
        "--force",
        "--create-reflog",
        "--column",
        "--omit-empty",
        "--color",
        "--ignore-case",
    ],
};

/// What a git command's arguments hold as message text.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Messages {
    /// Indices into the arguments of the words that are message text (a
    /// value after `-m`, or a word with the value glued on).
    pub words: Vec<usize>,
    /// The message is read from stdin (`-F -`, `--file=-`,
    /// `-F /dev/stdin`).
    pub stdin: bool,
}

/// Item 42: the message words of `git <sub> <args>`. Options are read as
/// git reads them; `--` ends the reading, so nothing after it counts as a
/// message. A message is data only while git cannot start an editor on
/// it: an edit option (`-e`, also in a cluster, `--edit`) gives no
/// message words, and so does an option the table does not know or an
/// abbreviated long option, since it can be one (`--edi`).
#[must_use]
pub fn message_words(sub: &str, args: &[String]) -> Messages {
    let opts = match sub {
        "commit" => &COMMIT,
        "merge" => &MERGE,
        "tag" => &TAG,
        _ => return Messages::default(),
    };
    let mut out = Messages::default();
    let from_stdin = |v: &str| v == "-" || v == "/dev/stdin";
    let mut i = 0;
    while let Some(a) = args.get(i) {
        let at = i;
        i += 1;
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v)),
                None => (a.clone(), None),
            };
            let valued = opts.long_valued.contains(&name.as_str());
            let negated = name.strip_prefix("--no-").is_some_and(|n| {
                let n = format!("--{n}");
                opts.long_valued.contains(&n.as_str()) || opts.long_flags.contains(&n.as_str())
            });
            if valued {
                let v = match value {
                    Some(v) => Some(v),
                    None => {
                        i += 1;
                        args.get(at + 1).map(String::as_str)
                    }
                };
                if name == "--message" && v.is_some() {
                    out.words.push(if value.is_some() { at } else { at + 1 });
                } else if name == "--file" && v.is_some_and(from_stdin) {
                    out.stdin = true;
                }
            } else if name == "--edit" || !(opts.long_flags.contains(&name.as_str()) || negated) {
                return Messages::default();
            }
            continue;
        }
        let Some(cluster) = a.strip_prefix('-') else {
            // A path, a branch or a tag name.
            continue;
        };
        if cluster.is_empty() {
            continue;
        }
        for (k, c) in cluster.char_indices() {
            let rest = &cluster[k + c.len_utf8()..];
            if c == 'e' {
                // `--edit` in all three.
                return Messages::default();
            }
            if opts.flags.contains(c) {
                continue;
            }
            if opts.glued.contains(c) {
                break;
            }
            if !opts.valued.contains(c) {
                // Unknown: git fails, or reads it some other way.
                return Messages::default();
            }
            let (value, word) = if rest.is_empty() {
                i += 1;
                (args.get(at + 1).map(String::as_str), at + 1)
            } else {
                (Some(rest), at)
            };
            if c == 'm' && value.is_some() {
                out.words.push(word);
            } else if c == 'F' && value.is_some_and(from_stdin) {
                out.stdin = true;
            }
            break;
        }
    }
    out
}

/// True when `c`, after a word, ends it for bash.
fn ends_word(c: Option<char>) -> bool {
    c.is_none_or(|c| matches!(c, ' ' | '\t' | '\n' | ';' | '&' | '|' | ')' | '<' | '>'))
}

/// True when bash reads `raw`, a whole word of the source, as exactly one
/// word with no expansion: quotes and backslashes only, no `$`, backtick,
/// glob, brace or tilde outside single quotes (a glob or a brace list can
/// turn one word into several, and a later one into an option).
#[must_use]
pub fn literal_word(raw: &str, before: Option<char>, after: Option<char>) -> bool {
    matches!(before, Some(' ' | '\t' | '\n')) && ends_word(after) && expands_nothing(raw)
}

/// True when `raw`, a whole word of the source that may also start the
/// command (`before` is `None` or ends a command), is one word bash
/// passes as written, as for [`literal_word`]. A word that expands
/// (`$E`, `*`, `{a,-e}`) can become an option, `-e` among them.
#[must_use]
pub fn plain_word(raw: &str, before: Option<char>, after: Option<char>) -> bool {
    before.is_none_or(|c| c.is_whitespace() || matches!(c, ';' | '&' | '|' | '('))
        && ends_word(after)
        && expands_nothing(raw)
}

/// True when `raw` has quotes and backslashes only: no `$`, backtick,
/// glob, brace, tilde or history char outside single quotes, and no
/// blank or operator outside quotes.
pub(crate) fn expands_nothing(raw: &str) -> bool {
    let mut it = raw.chars();
    while let Some(c) = it.next() {
        match c {
            '\'' => loop {
                match it.next() {
                    Some('\'') => break,
                    Some(_) => {}
                    None => return false,
                }
            },
            '"' => loop {
                match it.next() {
                    Some('"') => break,
                    Some('\\') => {
                        if it.next().is_none() {
                            return false;
                        }
                    }
                    Some('$' | '`') | None => return false,
                    Some(_) => {}
                }
            },
            '\\' => {
                if it.next().is_none() {
                    return false;
                }
            }
            '$' | '`' | '*' | '?' | '[' | '{' | '}' | '~' | '!' => return false,
            c if c.is_whitespace() || matches!(c, ';' | '&' | '|' | '(' | ')' | '<' | '>') => {
                return false;
            }
            _ => {}
        }
    }
    true
}

/// True when `raw`, a whole word of the source, is exactly
/// `"$(cat <<'D'` newline, body lines, a line `D`, `)"` (the form Claude
/// Code writes commit messages in): a quoted delimiter, so bash expands
/// nothing in the body, and nothing but blanks after the delimiter line.
#[must_use]
pub fn cat_heredoc_word(raw: &str, before: Option<char>, after: Option<char>) -> bool {
    if !matches!(before, Some(' ' | '\t' | '\n')) || !ends_word(after) {
        return false;
    }
    fn blank(s: &str) -> &str {
        s.trim_start_matches([' ', '\t'])
    }
    let Some(inner) = raw.strip_prefix("\"$(").and_then(|r| r.strip_suffix(")\"")) else {
        return false;
    };
    let Some(rest) = blank(inner).strip_prefix("cat") else {
        return false;
    };
    let Some(rest) = blank(rest).strip_prefix("<<") else {
        return false;
    };
    let rest = blank(rest);
    let Some(quote) = rest.chars().next().filter(|q| matches!(q, '\'' | '"')) else {
        return false;
    };
    let rest = &rest[1..];
    let Some(end) = rest.find(quote) else {
        return false;
    };
    let delim = &rest[..end];
    if delim.is_empty() || !delim.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    let rest = blank(&rest[end + 1..]);
    let Some(body) = rest.strip_prefix('\n') else {
        return false;
    };
    let mut at = 0;
    for line in body.split_inclusive('\n') {
        at += line.len();
        if line.strip_suffix('\n') == Some(delim) {
            return body[at..].chars().all(|c| matches!(c, ' ' | '\t' | '\n'));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn message_words_follow_git_option_parsing() {
        let m = |sub: &str, s: &str| message_words(sub, &args(s)).words;
        assert_eq!(m("commit", "-m x"), vec![1]);
        assert_eq!(m("commit", "-am x -m y"), vec![1, 3]);
        assert_eq!(m("commit", "-mx"), vec![0]);
        assert_eq!(m("commit", "--message=x"), vec![0]);
        assert_eq!(m("commit", "--message x"), vec![1]);
        assert_eq!(m("commit", "a.rs -m x"), vec![2]);
        assert_eq!(m("commit", "-q --amend -s -m x"), vec![4]);
        assert_eq!(m("commit", "--author a -m x"), vec![3]);
        // Values of other options are not messages, and git reads the word
        // after them as an option again.
        assert!(m("commit", "-F -m x").is_empty());
        assert!(m("commit", "-C -m x").is_empty());
        assert!(m("commit", "--author -m x").is_empty());
        // `-u` takes the rest of its word: `-um` is mode `m`.
        assert!(m("commit", "-um x").is_empty());
        // `--` ends the reading.
        assert!(m("commit", "-- -m x").is_empty());
        assert_eq!(m("commit", "-m a -- -e"), vec![1]);
        // An unknown option or an abbreviation can be one that edits.
        assert!(m("commit", "-m a -Z -m b").is_empty());
        assert!(m("commit", "-m a --mess b").is_empty());
        assert!(m("commit", "-m a --bogus -m b").is_empty());
        assert!(m("tag", "-a -m a --edi t1").is_empty());
        // An edit option runs the editor on the message.
        assert!(m("commit", "-m a -e").is_empty());
        assert!(m("commit", "-ve -m a").is_empty());
        assert!(m("commit", "--edit -m a").is_empty());
        assert!(m("commit", "-m a --no-edit --edit").is_empty());
        assert!(m("tag", "-a -em a t1").is_empty());
        assert!(m("merge", "-e -m a feat").is_empty());
        assert!(!message_words("tag", &args("-e -F -")).stdin);
        assert_eq!(m("commit", "--no-edit -m a"), vec![2]);
        assert_eq!(m("merge", "--no-edit -m a feat"), vec![2]);
        // A negated valued option takes no value.
        assert_eq!(m("commit", "--no-author -m x"), vec![2]);
        assert_eq!(m("tag", "--no-contains HEAD -m x"), vec![3]);
        assert_eq!(m("merge", "--no-ff -m x feat"), vec![2]);
        assert!(m("push", "-m x").is_empty());
        assert!(message_words("commit", &args("-F -")).stdin);
        assert!(message_words("commit", &args("--file=-")).stdin);
        assert!(message_words("commit", &args("--file /dev/stdin")).stdin);
        assert!(message_words("commit", &args("-F-")).stdin);
        assert!(!message_words("commit", &args("-F m.txt")).stdin);
    }

    #[test]
    fn literal_words_have_no_expansion() {
        let lit = |s: &str| literal_word(s, Some(' '), None);
        for w in [
            "x",
            "'a b --no-verify'",
            "\"a b\"",
            "'it'\"'\"'s'",
            "\"a\\\"b\"",
            "\"cost \\$5\"",
            "'$HOME'",
        ] {
            assert!(lit(w), "{w}");
        }
        for w in [
            "$x",
            "\"$x\"",
            "\"`x`\"",
            "{a,--no-verify}",
            "--no-verif?",
            "*",
            "[a]",
            "~",
            "'open",
            "\"open",
            "a b",
            "a;b",
        ] {
            assert!(!lit(w), "{w}");
        }
        assert!(!literal_word("x", Some('='), None));
        assert!(!literal_word("x", Some(' '), Some('x')));
        // `plain_word` also takes the first word of a command.
        assert!(plain_word("git", None, Some(' ')));
        assert!(plain_word("git", Some(';'), Some(' ')));
        assert!(plain_word("\"-e\"", Some(' '), None));
        assert!(!plain_word("git", Some('='), Some(' ')));
        for w in ["$E", "\"$E\"", "*", "{-e,x}", "~", "$(x)", "a b"] {
            assert!(!plain_word(w, Some(' '), None), "{w}");
        }
    }

    #[test]
    fn cat_heredoc_words_are_exact() {
        let ok = |s: &str| cat_heredoc_word(s, Some(' '), None);
        assert!(ok("\"$(cat <<'EOF'\nsubject\n\nbody\nEOF\n)\""));
        assert!(ok("\"$(cat <<\"EOF\"\nx ) \" $(y)\nEOF\n  )\""));
        assert!(ok("\"$(cat<<'M_1'\nx\nM_1\n)\""));
        for w in [
            "\"$(cat <<EOF\nx\nEOF\n)\"",
            "\"$(cat <<-'EOF'\nx\nEOF\n)\"",
            "\"$(cat <<'EOF'\nx\nEOF\necho y)\"",
            "\"$(cat <<'EOF'\nx\n)\"",
            "\"$(cat <<'EOF' x\nx\nEOF\n)\"",
            "\"$(cat a <<'EOF'\nx\nEOF\n)\"",
            "\"$(cat <<'E F'\nx\nE F\n)\"",
            "\"$(tac <<'EOF'\nx\nEOF\n)\"",
            "$(cat <<'EOF'\nx\nEOF\n)",
        ] {
            assert!(!ok(w), "{w}");
        }
    }
}
