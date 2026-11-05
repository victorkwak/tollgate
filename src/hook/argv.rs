//! The git command line that ran a hook, for the retry command of a deny
//! (L17: `tollgate wait <job> && git commit <same args>`).
//!
//! git does not pass its own arguments to hooks. On Linux the hook reads
//! its parent's `/proc/<ppid>/cmdline` (git, or a shell git used for a hook
//! path with special characters). On macOS the command line is not read
//! (L13): the deny message prints a placeholder.

use std::ffi::OsString;

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

/// The arguments (after `git`) of the git process that ran this hook,
/// when they can be read.
#[must_use]
pub fn parent_git_args() -> Option<Vec<OsString>> {
    platform::parent_git_args()
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    fn cmdline(pid: u32) -> Option<Vec<OsString>> {
        let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        Some(
            bytes
                .split(|b| *b == 0)
                .filter(|a| !a.is_empty())
                .map(|a| OsStr::from_bytes(a).to_owned())
                .collect(),
        )
    }

    fn ppid_of(pid: u32) -> Option<u32> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        // `pid (comm) state ppid ...`; comm may hold spaces and parens.
        let rest = &stat[stat.rfind(')')? + 1..];
        rest.split_whitespace().nth(1)?.parse().ok()
    }

    fn is_git(argv0: &OsStr) -> bool {
        Path::new(argv0).file_name() == Some(OsStr::new("git"))
    }

    pub(super) fn parent_git_args() -> Option<Vec<OsString>> {
        let mut pid = std::os::unix::process::parent_id();
        // git runs a hook directly, or through `sh -c` for a hook path with
        // special characters: look two levels up at most.
        for _ in 0..2 {
            let argv = cmdline(pid)?;
            if argv.first().is_some_and(|a| is_git(a)) {
                return Some(argv[1..].to_vec());
            }
            pid = ppid_of(pid)?;
        }
        None
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use std::ffi::OsString;

    pub(super) fn parent_git_args() -> Option<Vec<OsString>> {
        None
    }
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
