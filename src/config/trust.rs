//! Remote trust by parsed URL (item 34, X5).
//!
//! `scope.remotes` globs match loosely (case-insensitive, `*` crosses `/`),
//! which is right for scope: a look-alike URL is gated too. Trust grants
//! things (the L2 policy anchor, R56 trusted bases, R14(2) remote-verified
//! pushes), so it parses both sides:
//!
//! - URLs: `https://`, `ssh://` (`git+ssh://`, `ssh+git://`) and scp-like
//!   `[user@]host:path`. No other scheme: `http://` and `git://` have no
//!   server authentication, and local paths and `file://` name a dir any
//!   process can fill.
//! - Patterns: a `scope.remotes` entry with its leading `*` (any scheme and
//!   user) removed: `host:path`, `host/path`, or a URL with a scheme. The
//!   host matches exactly (case-insensitive), the port must be equal, and
//!   the path matches segment by segment, each a glob in which `*` never
//!   crosses `/`. The last URL segment also matches without `.git`.
//! - Local mirrors and test repos: `scope.trusted_paths`, exact canonical
//!   absolute paths, matched against a local path or `file://` URL that
//!   already is its canonical path (item 48: git reads the path as
//!   spelled, later, so a symlink in it could point elsewhere by then).

use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};

/// A URL scheme trust allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `https://`.
    Https,
    /// `ssh://` and scp-like `host:path`.
    Ssh,
}

/// A remote URL taken apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteUrl {
    /// Scheme.
    pub scheme: Scheme,
    /// Host, lowercase.
    pub host: String,
    /// Port, when the URL names one.
    pub port: Option<u16>,
    /// Path segments, none empty, `.` or `..`.
    pub path: Vec<String>,
}

/// A valid host: letters, digits, `.`, `-`, or a bracketed IPv6 address.
fn host_ok(h: &str) -> bool {
    if let Some(inner) = h.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    }
    !h.is_empty()
        && !h.starts_with(['.', '-'])
        && !h.ends_with('.')
        && h.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
}

/// Splits `host[:port]`.
fn host_port(authority: &str) -> Option<(String, Option<u16>)> {
    let (host, port) = if authority.starts_with('[') {
        let end = authority.find(']')?;
        let rest = &authority[end + 1..];
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p.parse().ok()?),
            None if rest.is_empty() => None,
            None => return None,
        };
        (&authority[..=end], port)
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p.parse().ok()?)),
            None => (authority, None),
        }
    };
    host_ok(host).then(|| (host.to_ascii_lowercase(), port))
}

/// Path segments of a URL path: no empty, `.`, `..` segment, no `%`
/// (an encoded `/` or `..`), backslash or control character.
fn segments(path: &str) -> Option<Vec<String>> {
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_suffix('/').unwrap_or(path);
    if path.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for seg in path.split('/') {
        let bad = seg.is_empty()
            || seg == "."
            || seg == ".."
            || seg.chars().any(|c| c == '%' || c == '\\' || c.is_control());
        if bad {
            return None;
        }
        out.push(seg.to_owned());
    }
    Some(out)
}

/// Item 47: a character that ends or re-reads a URL part in some parser
/// (`?` query, `#` fragment, `\` a `/` to WHATWG, `%` an encoding),
/// whitespace or a control character. A trusted URL has none, anywhere.
fn unsafe_url_char(c: char) -> bool {
    matches!(c, '?' | '#' | '\\' | '%') || c.is_whitespace() || c.is_control()
}

/// Item 47, review note 4: userinfo every parser reads the same way:
/// `[A-Za-z0-9._~-]+`, not starting with `-` (ssh would read an option;
/// git refuses it), and `:` (a password) only where `colon` allows it
/// (https). A `[` in it would end it for git, whose `host_end` reads a
/// leading `[` as a bracketed host: `[evil]x@host` connects to `evil`.
fn userinfo_ok(user: &str, colon: bool) -> bool {
    !user.is_empty()
        && !user.starts_with('-')
        && user.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'.' | b'_' | b'~' | b'-')
                || (colon && b == b':')
        })
}

/// `host[:port]` of an authority, without `user[:password]@`. Item 47:
/// more than one `@` (parsers split at the first or the last), an unsafe
/// character, or userinfo other than [`userinfo_ok`] (`colon`: a password
/// may follow `:`, https only) parses as nothing. A `[` can then only
/// start the host part, where [`host_port`] reads a bracketed IPv6
/// address as git does.
fn authority_host_port(authority: &str, colon: bool) -> Option<(String, Option<u16>)> {
    if authority.chars().any(unsafe_url_char) {
        return None;
    }
    let host = match authority.split_once('@') {
        Some((_, h)) if h.contains('@') => return None,
        Some((u, _)) if !userinfo_ok(u, colon) => return None,
        Some((_, h)) => h,
        None => authority,
    };
    host_port(host)
}

/// Parses a remote URL as git would reach a server; `None` for a local
/// path, `file://`, any other scheme, or a malformed URL. Item 47: the
/// authority ends at the first `/`, `?` or `#` (RFC 3986, curl), and a
/// URL with `?`, `#`, `\`, `%`, whitespace or a control character is
/// malformed here, so the host is the one git and curl connect to. The
/// scheme is lowercase as git spells it: git runs `HTTPS://` through a
/// `git-remote-HTTPS` helper found on PATH, not its own transport.
#[must_use]
pub fn parse_url(url: &str) -> Option<RemoteUrl> {
    if url.chars().any(unsafe_url_char) {
        return None;
    }
    if let Some((scheme, rest)) = url.split_once("://") {
        let scheme = match scheme {
            "https" => Scheme::Https,
            "ssh" | "git+ssh" | "ssh+git" => Scheme::Ssh,
            _ => return None,
        };
        let (authority, path) = rest.split_once('/')?;
        if path.starts_with('/') {
            return None;
        }
        let (host, port) = authority_host_port(authority, scheme == Scheme::Https)?;
        return Some(RemoteUrl {
            scheme,
            host,
            port,
            path: segments(path)?,
        });
    }
    // scp-like: a `:` before any `/`, and not a local path.
    if url.starts_with(['/', '.', '~']) {
        return None;
    }
    let colon = url.find(':')?;
    if url[..colon].contains('/') {
        return None;
    }
    let (authority, path) = url.split_at(colon);
    let (host, port) = authority_host_port(authority, false)?;
    if port.is_some() {
        return None;
    }
    Some(RemoteUrl {
        scheme: Scheme::Ssh,
        host,
        port: None,
        path: segments(&path[1..])?,
    })
}

/// A `scope.remotes` entry as a trust pattern.
#[derive(Debug, Clone)]
pub struct TrustPattern {
    scheme: Option<Scheme>,
    host: String,
    port: Option<u16>,
    path: Vec<GlobMatcher>,
}

impl TrustPattern {
    /// Parses `pattern`; `None` when it names no exact host and path (it
    /// then counts for scope only).
    #[must_use]
    pub fn parse(pattern: &str) -> Option<Self> {
        let p = pattern.trim_start_matches('*');
        let (scheme, host, port, path) = if p.contains("://") {
            let u = parse_url_pattern(p)?;
            (Some(u.0), u.1, u.2, u.3)
        } else {
            // `host:path` (scp-like) or `host/path`, any allowed scheme.
            let cut = p.find([':', '/'])?;
            let (authority, rest) = p.split_at(cut);
            let (host, port) = authority_host_port(authority, false)?;
            (None, host, port, rest[1..].to_owned())
        };
        let path = segments(&path)?
            .iter()
            .map(|seg| {
                GlobBuilder::new(seg)
                    .literal_separator(true)
                    .build()
                    .ok()
                    .map(|g| g.compile_matcher())
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self {
            scheme,
            host,
            port,
            path,
        })
    }

    /// True when `url` is this pattern's server and path.
    #[must_use]
    pub fn matches(&self, url: &RemoteUrl) -> bool {
        if self.scheme.is_some_and(|s| s != url.scheme)
            || self.host != url.host
            || self.port != url.port
            || self.path.len() != url.path.len()
        {
            return false;
        }
        let last = url.path.len() - 1;
        self.path
            .iter()
            .zip(&url.path)
            .enumerate()
            .all(|(i, (g, seg))| {
                g.is_match(seg)
                    || (i == last
                        && seg
                            .strip_suffix(".git")
                            .is_some_and(|s| !s.is_empty() && g.is_match(s)))
            })
    }
}

/// `scheme://[user@]host[:port]/path` of a pattern.
fn parse_url_pattern(p: &str) -> Option<(Scheme, String, Option<u16>, String)> {
    let (scheme, rest) = p.split_once("://")?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "https" => Scheme::Https,
        "ssh" | "git+ssh" | "ssh+git" => Scheme::Ssh,
        _ => return None,
    };
    let (authority, path) = rest.split_once('/')?;
    let (host, port) = authority_host_port(authority, scheme == Scheme::Https)?;
    Some((scheme, host, port, path.to_owned()))
}

/// The absolute path a local URL spells (`/abs`, `file:///abs`), as git
/// reads it. `None` for anything else, for a control character, and for
/// a `file://` URL with an unsafe URL character: git decodes `%` there.
fn local_spelling(url: &str) -> Option<&str> {
    let p = match url.strip_prefix("file://") {
        Some(p) if p.chars().any(unsafe_url_char) => return None,
        Some(p) => p,
        None if url.chars().any(char::is_control) => return None,
        None => url,
    };
    p.starts_with('/').then_some(p)
}

/// The canonical path of the dir a local URL names, however it is
/// spelled; `None` for anything else or a path that does not exist.
#[must_use]
pub fn canonical_local(url: &str) -> Option<PathBuf> {
    std::fs::canonicalize(local_spelling(url)?).ok()
}

/// Item 48: the path a local URL names when the URL already spells its
/// canonical path: no symlink part, no `.` or `..`, no repeated or
/// trailing `/`. Git reads the path as spelled when it runs, so another
/// spelling could reach another dir by then (a symlink swapped after this
/// check); such a URL names nothing trusted. Residual: the same user can
/// still change the canonical dir itself (X5).
#[must_use]
pub fn local_path(url: &str) -> Option<PathBuf> {
    let spelled = local_spelling(url)?;
    let canonical = std::fs::canonicalize(spelled).ok()?;
    (canonical.as_os_str() == std::ffi::OsStr::new(spelled)).then_some(canonical)
}

/// Item 33: the identity of a remote URL, for comparing a URL recorded
/// earlier with the URLs a repo has now. A parsed URL gives its scheme,
/// lowercase host, port and path segments, the last without `.git`
/// (`git@gitlab.com:g/r.git` and `ssh://gitlab.com/g/r` are one; https and
/// ssh are not). Anything else (a local path, `file://`) gives its path
/// without `file://`, made lexically normal (no `.` parts, no repeated or
/// trailing `/`; `..` stays), without reading the file system.
#[must_use]
pub fn url_identity(url: &str) -> String {
    if let Some(u) = parse_url(url) {
        let scheme = match u.scheme {
            Scheme::Https => "https",
            Scheme::Ssh => "ssh",
        };
        let port = u.port.map(|p| format!(":{p}")).unwrap_or_default();
        let mut path = u.path;
        if let Some(last) = path.last_mut()
            && let Some(s) = last.strip_suffix(".git")
            && !s.is_empty()
        {
            *last = s.to_owned();
        }
        return format!("{scheme}://{}{port}/{}", u.host, path.join("/"));
    }
    let p = url.strip_prefix("file://").unwrap_or(url);
    let normal: PathBuf = Path::new(p)
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect();
    format!("local:{}", normal.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Item 33: the same server and repo in another spelling is one
    /// identity; another scheme, port, host or repo is not.
    #[test]
    fn url_identity_is_the_parsed_server_and_path_item33() {
        let id = url_identity;
        let r = id("https://gitlab.com/victorkwak/r.git");
        for same in [
            "https://GitLab.com/victorkwak/r",
            "https://user@gitlab.com/victorkwak/r.git/",
        ] {
            assert_eq!(id(same), r, "{same}");
        }
        for other in [
            // Item 47: git runs `HTTPS://` through another helper, and
            // curl connects to `evil` for `evil?@gitlab.com`.
            "HTTPS://gitlab.com/victorkwak/r.git",
            "https://evil?@gitlab.com/victorkwak/r.git",
            "ssh://gitlab.com/victorkwak/r.git",
            "https://gitlab.com:8443/victorkwak/r.git",
            "https://gitlab.com.evil.example/victorkwak/r.git",
            "https://gitlab.com/victorkwak/R.git",
            "https://gitlab.com/victorkwak/r.git.git",
            "https://evil.example/gitlab.com/victorkwak/r.git",
            "/tmp/gitlab.com/victorkwak/r.git",
        ] {
            assert_ne!(id(other), r, "{other}");
        }
        let s = id("git@gitlab.com:victorkwak/r.git");
        assert_eq!(id("ssh://git@gitlab.com/victorkwak/r"), s);
        assert_eq!(id("git+ssh://gitlab.com/victorkwak/r.git"), s);
        let l = id("/srv/mirror/r.git");
        for same in ["file:///srv/mirror/r.git", "/srv//mirror/./r.git/"] {
            assert_eq!(id(same), l, "{same}");
        }
        for other in [
            "/srv/mirror/r",
            "/srv/x/../mirror/r.git",
            "srv/mirror/r.git",
        ] {
            assert_ne!(id(other), l, "{other}");
        }
    }

    /// Item 47: the authority ends at the first `/`, `?` or `#`, as curl
    /// and git read it, and a URL with `?`, `#`, `\`, `%`, whitespace, a
    /// control character or a second `@` is never parsed (so never
    /// trusted). `https://evil?@gitlab.com/g/r` connects to `evil`.
    #[test]
    fn authority_ends_at_query_or_fragment_item47() {
        let p = TrustPattern::parse("*gitlab.com/victorkwak/*").unwrap();
        let trusted = |u: &str| parse_url(u).is_some_and(|u| p.matches(&u));
        for url in [
            "https://evil?@gitlab.com/victorkwak/r",
            "https://evil#@gitlab.com/victorkwak/r",
            "https://evil.example?x@gitlab.com/victorkwak/r",
            "https://evil\\@gitlab.com/victorkwak/r",
            "https://evil%40@gitlab.com/victorkwak/r",
            "https://evil%2f@gitlab.com/victorkwak/r",
            "https://a@b@gitlab.com/victorkwak/r",
            "https://ev il@gitlab.com/victorkwak/r",
            "https://evil\t@gitlab.com/victorkwak/r",
            "https://evil\n@gitlab.com/victorkwak/r",
            "https://gitlab.com/victorkwak/r?x",
            "https://gitlab.com/victorkwak/r#x",
            "https://gitlab.com/victorkwak/r?@evil/x",
            "ssh://evil?@gitlab.com/victorkwak/r",
            "ssh://evil#@gitlab.com/victorkwak/r",
            "evil?@gitlab.com:victorkwak/r",
            "evil#@gitlab.com:victorkwak/r",
            "evil\\@gitlab.com:victorkwak/r",
            "evil%40@gitlab.com:victorkwak/r",
            "a@b@gitlab.com:victorkwak/r",
            "gitlab.com:victorkwak/r?x",
            // Trailing-dot host (another name to a string matcher), and a
            // scheme in capitals: git runs a `git-remote-HTTPS` helper
            // found on PATH, not its https transport.
            "https://gitlab.com./victorkwak/r",
            "gitlab.com.:victorkwak/r",
            "HTTPS://gitlab.com/victorkwak/r",
            "Ssh://gitlab.com/victorkwak/r",
        ] {
            assert!(!trusted(url), "{url:?} trusted");
        }
        for url in [
            "https://GITLAB.COM/victorkwak/r",
            "https://oauth2:tok-en_1.x~@gitlab.com/victorkwak/r",
            "ssh://git@GitLab.com/victorkwak/r.git",
            "git@GITLAB.com:victorkwak/r.git",
        ] {
            assert!(trusted(url), "{url:?} not trusted");
        }
        // A pattern spelled with the same tricks names no host.
        for pat in [
            "*evil?@gitlab.com/victorkwak/*",
            "*evil#@gitlab.com/victorkwak/*",
            "*a@b@gitlab.com/victorkwak/*",
            "*evil%40@gitlab.com:victorkwak/*",
        ] {
            assert!(TrustPattern::parse(pat).is_none(), "{pat:?}");
        }
    }

    /// Item 47, review note 4: git reads a leading `[` as a bracketed
    /// host, so `ssh://[evil.com]x@gitlab.com/...` and the scp-like
    /// `[evil.com]x@gitlab.com:...` connect to `evil.com`. Userinfo is
    /// `[A-Za-z0-9._~-]+` (plus `:` for https only): any other character
    /// in it parses as nothing.
    #[test]
    fn userinfo_with_a_bracket_or_other_character_is_never_trusted_item47() {
        let p = TrustPattern::parse("*gitlab.com/victorkwak/*").unwrap();
        let trusted = |u: &str| parse_url(u).is_some_and(|u| p.matches(&u));
        for url in [
            "ssh://[evil.com]x@gitlab.com/victorkwak/r",
            "ssh://[evil.com]@gitlab.com/victorkwak/r",
            "git+ssh://[evil.com]x@gitlab.com/victorkwak/r",
            "[evil.com]x@gitlab.com:victorkwak/r",
            "[evil.com]@gitlab.com:victorkwak/r",
            "https://[evil.com]x@gitlab.com/victorkwak/r",
            "ssh://u[x@gitlab.com/victorkwak/r",
            "ssh://u]x@gitlab.com/victorkwak/r",
            "u]x@gitlab.com:victorkwak/r",
            "ssh://@gitlab.com/victorkwak/r",
            "@gitlab.com:victorkwak/r",
            "ssh://-oProxyCommand=x@gitlab.com/victorkwak/r",
            "ssh://a:b@gitlab.com/victorkwak/r",
            "ssh://a!b@gitlab.com/victorkwak/r",
            "ssh://a;b@gitlab.com/victorkwak/r",
            "ssh://a$b@gitlab.com/victorkwak/r",
            "ssh://\u{e9}@gitlab.com/victorkwak/r",
            "https://a'b@gitlab.com/victorkwak/r",
            "https://a+b@gitlab.com/victorkwak/r",
        ] {
            assert!(!trusted(url), "{url:?} trusted");
        }
        for url in [
            "ssh://git@gitlab.com/victorkwak/r",
            "ssh://g.i_t~-1@gitlab.com/victorkwak/r",
            "git@gitlab.com:victorkwak/r",
            "https://oauth2:tok@gitlab.com/victorkwak/r",
            "https://user@gitlab.com/victorkwak/r",
        ] {
            assert!(trusted(url), "{url:?} not trusted");
        }
        for pat in [
            "*[evil.com]x@gitlab.com:victorkwak/*",
            "ssh://[evil.com]x@gitlab.com/victorkwak/*",
            "https://[evil.com]x@gitlab.com/victorkwak/*",
            "ssh://a:b@gitlab.com/victorkwak/*",
        ] {
            assert!(TrustPattern::parse(pat).is_none(), "{pat:?}");
        }
    }

    /// Item 47, review note 4: every ssh URL this parser accepts names
    /// the host, port and path that git itself reads
    /// (`git fetch-pack --diag-url`). The corpus mixes plain URLs with
    /// spellings where parsers disagree.
    #[test]
    fn accepted_ssh_urls_name_the_host_git_reads_item47() {
        let dir = tempfile::tempdir().unwrap();
        let git = crate::gitx::program();
        let init = std::process::Command::new(git)
            .args(["init", "-q"])
            .current_dir(dir.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(init.status.success(), "{init:?}");
        let corpus = [
            "ssh://git@gitlab.com/victorkwak/r.git",
            "ssh://gitlab.com/victorkwak/r",
            "ssh://git@GitLab.com:2222/victorkwak/r",
            "git+ssh://git@gitlab.com/victorkwak/r",
            "ssh+git://git@gitlab.com/victorkwak/r",
            "ssh://git@[::1]:22/victorkwak/r",
            "ssh://[::1]/victorkwak/r",
            "ssh://g.i_t~-1@gitlab.com/victorkwak/r",
            "git@gitlab.com:victorkwak/r.git",
            "gitlab.com:victorkwak/r",
            "ssh://[evil.com]x@gitlab.com/victorkwak/r",
            "ssh://[evil.com]@gitlab.com/victorkwak/r",
            "[evil.com]x@gitlab.com:victorkwak/r",
            "[git@evil.com]:victorkwak/r",
            "git@[evil.com]x@gitlab.com:victorkwak/r",
            "ssh://u[x@gitlab.com/victorkwak/r",
            "ssh://u]x@gitlab.com/victorkwak/r",
            "ssh://[git@evil.com]:22/victorkwak/r",
            "ssh://git@[gitlab.com]/victorkwak/r",
            "ssh://git@gitlab.com:x/victorkwak/r",
            "ssh://a:b@gitlab.com/victorkwak/r",
            "a:b@gitlab.com:victorkwak/r",
            "git@[::1]:victorkwak/r",
            "ssh://-oProxyCommand=x@gitlab.com/victorkwak/r",
        ];
        let mut accepted = 0;
        for url in corpus {
            let Some(u) = parse_url(url) else { continue };
            accepted += 1;
            let out = std::process::Command::new(git)
                .args(["fetch-pack", "--diag-url", url])
                .current_dir(dir.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            let field = |k: &str| {
                text.lines()
                    .find_map(|l| l.strip_prefix(&format!("Diag: {k}=")))
                    .unwrap_or_else(|| panic!("{url:?}: no {k} in {text}"))
                    .to_owned()
            };
            let userandhost = field("userandhost");
            let host = userandhost.rsplit('@').next().unwrap().to_ascii_lowercase();
            let ours = u.host.trim_start_matches('[').trim_end_matches(']');
            assert_eq!(ours, host, "{url:?}: git reads {userandhost}");
            let port = field("port");
            let port = (port != "NONE").then(|| port.parse::<u16>().unwrap());
            assert_eq!(u.port, port, "{url:?}");
            assert_eq!(Some(u.path.clone()), segments(&field("path")), "{url:?}");
        }
        assert!(accepted >= 10, "only {accepted} accepted");
    }
}
