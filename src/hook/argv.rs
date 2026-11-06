//! The git command line that ran a hook, for the retry command of a deny
//! (L17: `tollgate wait <job> && git commit <same args>`).
//!
//! git does not pass its own arguments to hooks, so the hook reads its
//! parent's arguments (git, or a shell git used for a hook path with special
//! characters): `/proc/<ppid>/cmdline` on Linux, `KERN_PROCARGS2` on macOS.
//! When they cannot be read, the deny message prints a placeholder.

use std::ffi::{OsStr, OsString};
use std::path::Path;

/// Quotes `arg` for a POSIX shell when it needs quoting.
#[must_use]
pub fn shell_quote(arg: &str) -> String {
    let plain = !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'-' | b'_' | b'.' | b'/' | b':' | b'=' | b'@' | b'+' | b',' | b'%'
                )
        });
    if plain {
        arg.to_owned()
    } else {
        format!("'{}'", arg.replace('\'', "'\\''"))
    }
}

/// `git <args>` with each argument quoted.
#[must_use]
pub fn git_command_text(args: &[OsString]) -> String {
    let mut out = String::from("git");
    for a in args {
        out.push(' ');
        out.push_str(&shell_quote(&a.to_string_lossy()));
    }
    out
}

fn is_git(argv0: &OsStr) -> bool {
    Path::new(argv0).file_name() == Some(OsStr::new("git"))
}

/// The arguments (after `git`) of the git process that ran this hook,
/// when they can be read.
#[must_use]
pub fn parent_git_args() -> Option<Vec<OsString>> {
    let mut pid = std::os::unix::process::parent_id().cast_signed();
    // git runs a hook directly, or through `sh -c` for a hook path with
    // special characters: look two levels up at most.
    for _ in 0..2 {
        let argv = crate::procs::argv(pid)?;
        if argv.first().is_some_and(|a| is_git(a)) {
            return Some(argv[1..].to_vec());
        }
        pid = crate::procs::parent_of(pid)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_keeps_plain_words_and_quotes_the_rest_l17() {
        assert_eq!(shell_quote("commit"), "commit");
        assert_eq!(shell_quote("-m"), "-m");
        assert_eq!(shell_quote("fix: a b"), "'fix: a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(
            git_command_text(&["commit".into(), "-m".into(), "two words".into()]),
            "git commit -m 'two words'"
        );
    }
}
