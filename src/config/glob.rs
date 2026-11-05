//! Glob compilation for config patterns.

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

/// How a pattern list matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobOpts {
    /// Match without regard to ASCII case.
    pub case_insensitive: bool,
    /// `*` and `?` do not match `/` (only `**` crosses directories).
    pub literal_separator: bool,
}

/// Compiles `patterns` into one set. The error names the bad pattern.
pub fn compile<S: AsRef<str>>(patterns: &[S], opts: GlobOpts) -> Result<GlobSet, String> {
    let mut set = GlobSetBuilder::new();
    for p in patterns {
        let p = p.as_ref();
        let glob = GlobBuilder::new(p)
            .case_insensitive(opts.case_insensitive)
            .literal_separator(opts.literal_separator)
            .backslash_escape(true)
            .build()
            .map_err(|e| format!("invalid glob {p:?}: {}", e.kind()))?;
        set.add(glob);
    }
    set.build().map_err(|e| format!("invalid glob set: {e}"))
}

/// Checks that one pattern compiles.
pub fn check(pattern: &str) -> Result<(), String> {
    compile(
        &[pattern],
        GlobOpts {
            case_insensitive: false,
            literal_separator: false,
        },
    )
    .map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_change_matching() {
        let loose = compile(
            &["integration/*"],
            GlobOpts {
                case_insensitive: true,
                literal_separator: false,
            },
        )
        .unwrap();
        assert!(loose.is_match("Integration/a/b"));
        let strict = compile(
            &["wip/*"],
            GlobOpts {
                case_insensitive: false,
                literal_separator: true,
            },
        )
        .unwrap();
        assert!(strict.is_match("wip/a"));
        assert!(!strict.is_match("wip/a/b"));
        assert!(!strict.is_match("WIP/a"));
    }

    #[test]
    fn bad_patterns_are_named() {
        let err = check("a[").unwrap_err();
        assert!(err.contains("a["), "{err}");
    }
}
