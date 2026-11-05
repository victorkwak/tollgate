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
//!   absolute paths, matched against a local path or `file://` URL after
//!   canonicalization.

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

/// Drops `user[:password]@` from an authority.
fn without_user(authority: &str) -> &str {
    authority.rsplit_once('@').map_or(authority, |(_, h)| h)
}

/// Parses a remote URL as git would reach a server; `None` for a local
/// path, `file://`, any other scheme, or a malformed URL.
#[must_use]
pub fn parse_url(url: &str) -> Option<RemoteUrl> {
    if let Some((scheme, rest)) = url.split_once("://") {
        let scheme = match scheme.to_ascii_lowercase().as_str() {
            "https" => Scheme::Https,
            "ssh" | "git+ssh" | "ssh+git" => Scheme::Ssh,
            _ => return None,
        };
        let (authority, path) = rest.split_once('/')?;
        if path.starts_with('/') {
            return None;
        }
        let (host, port) = host_port(without_user(authority))?;
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
    let (host, port) = host_port(without_user(authority))?;
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
            let (host, port) = host_port(without_user(authority))?;
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
    let (host, port) = host_port(without_user(authority))?;
    Some((scheme, host, port, path.to_owned()))
}

/// The local path a URL names (`/abs`, `file:///abs`), canonical; `None`
/// for anything else or a path that does not exist.
#[must_use]
pub fn local_path(url: &str) -> Option<PathBuf> {
    let p = url.strip_prefix("file://").unwrap_or(url);
    let p = Path::new(p);
    if !p.is_absolute() {
        return None;
    }
    std::fs::canonicalize(p).ok()
}
