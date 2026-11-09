//! fetch, pull and push as git reads them (G7, item 22, secreview note 7):
//! which repo the repository argument reaches, and which local refs a
//! refspec destination names.
//!
//! git looks a repository argument up as a remote name first (its `url`,
//! `pushurl`, `url.<base>.insteadOf` and `pushInsteadOf` from every config
//! file it reads), and reads any other word as a URL or a path. A path
//! (`.`, `./`, `.git`, `../repo`, `/abs`, `repo2`, `file://...`) is
//! relative to the worktree top (git changes to it first). The config
//! files are parsed here with no subprocess ([`crate::gitx::config_file`]);
//! when they cannot be read that way, a word that may name a remote counts
//! as the local repo (fail closed).

use std::path::{Path, PathBuf};

use crate::env::EnvSnapshot;
use crate::gitx::RepoLayout;
use crate::gitx::config_file::{self, Entry};
use crate::gitx::hooks_path;
use crate::gitx::ref_files::{self, Head};

/// System config files of the git builds tollgate runs with (Arch, Homebrew
/// on Apple silicon and Intel, Xcode). Reading one git does not read only
/// adds remotes and rewrites, which makes the guard stricter.
const SYSTEM_CONFIGS: &[&str] = &[
    "/etc/gitconfig",
    "/opt/homebrew/etc/gitconfig",
    "/usr/local/etc/gitconfig",
    "/Library/Developer/CommandLineTools/usr/share/git-core/gitconfig",
    "/Applications/Xcode.app/Contents/Developer/usr/share/git-core/gitconfig",
];

/// The repo a git command runs in, as the guard reads it.
pub(super) enum Repo {
    /// No repo: git refuses fetch, pull and push.
    Absent,
    /// A repo whose layout the files do not show (fail closed).
    Unreadable,
    Found(Found),
}

pub(super) struct Found {
    pub layout: RepoLayout,
    /// Every config entry git reads, in order; `None` when the files
    /// cannot be read without git (include, syntax error, a variable).
    pub config: Option<Vec<Entry>>,
}

/// True for a dir git takes as a git dir.
fn is_git_dir(p: &Path) -> bool {
    p.join("HEAD").is_file() && (p.join("objects").is_dir() || p.join("commondir").is_file())
}

/// The repo git finds from `dir`, with the config the command adds:
/// `configs` from `-c`, `config_env` when `--config-env` is given.
pub(super) fn open(dir: &Path, env: &EnvSnapshot, configs: &[String], config_env: bool) -> Repo {
    if env.get("GIT_COMMON_DIR").is_some() {
        return Repo::Unreadable;
    }
    let root = if env.get_nonempty("GIT_DIR").is_some() {
        dir.to_owned()
    } else {
        match dir
            .ancestors()
            .find(|a| a.join(".git").symlink_metadata().is_ok() || is_git_dir(a))
        {
            Some(r) => r.to_owned(),
            None => return Repo::Absent,
        }
    };
    let Some(layout) = RepoLayout::for_hook(&root, env) else {
        return Repo::Unreadable;
    };
    let config = read_config(&layout, env, configs, config_env);
    Repo::Found(Found { layout, config })
}

fn read_config(
    layout: &RepoLayout,
    env: &EnvSnapshot,
    configs: &[String],
    config_env: bool,
) -> Option<Vec<Entry>> {
    if config_env || env.get_nonempty("GIT_CONFIG_PARAMETERS").is_some() {
        return None;
    }
    let nosystem = match env.get("GIT_CONFIG_NOSYSTEM") {
        None => false,
        Some(v) => config_file::parse_bool(Some(v.to_str()?))?,
    };
    let mut files: Vec<PathBuf> = Vec::new();
    if !nosystem && env.get("GIT_CONFIG_SYSTEM").is_none() {
        files.extend(SYSTEM_CONFIGS.iter().map(PathBuf::from));
    }
    files.extend(hooks_path::config_files(layout, env, None).ok()?);
    let mut entries = Vec::new();
    for f in files {
        if let Some(e) = hooks_path::read_entries(&f).ok()? {
            entries.extend(e);
        }
    }
    if let Some(n) = env.get("GIT_CONFIG_COUNT") {
        let n: usize = n.to_str()?.trim().parse().ok()?;
        for i in 0..n {
            let k = env.get(&format!("GIT_CONFIG_KEY_{i}"))?.to_str()?;
            let v = env.get(&format!("GIT_CONFIG_VALUE_{i}"))?.to_str()?;
            entries.push(entry(k, Some(v))?);
        }
    }
    for c in configs {
        let (k, v) = match c.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (c.as_str(), None),
        };
        entries.push(entry(k, v)?);
    }
    Some(entries)
}

/// `section[.subsection].key` as the parser writes it: section and key
/// lowercased, the subsection as written.
fn entry(key: &str, value: Option<&str>) -> Option<Entry> {
    let (section, rest) = key.split_once('.')?;
    let (sub, name) = match rest.rsplit_once('.') {
        Some((s, n)) => (Some(s), n),
        None => (None, rest),
    };
    let mut section = section.to_ascii_lowercase();
    if let Some(s) = sub {
        section.push('.');
        section.push_str(s);
    }
    Some(Entry {
        section,
        key: name.to_ascii_lowercase(),
        value: value.map(str::to_owned),
    })
}

impl Found {
    /// The values of `remote.<name>.<key>` in order, an empty value
    /// clearing the list; `None` for a bare key (git refuses it).
    fn list(entries: &[Entry], name: &str, key: &str) -> Option<Vec<String>> {
        let section = format!("remote.{name}");
        let mut out = Vec::new();
        for e in entries
            .iter()
            .filter(|e| e.section == section && e.key == key)
        {
            match e.value.as_deref() {
                None => return None,
                Some("") => out.clear(),
                Some(v) => out.push(v.to_owned()),
            }
        }
        Some(out)
    }

    /// The last value of `section.key`.
    pub fn get(&self, section: &str, key: &str) -> Option<&str> {
        config_file::last(self.config.as_deref()?, section, key)?
            .value
            .as_deref()
    }

    /// True when config defines remote `name`.
    pub fn is_remote(&self, name: &str) -> Option<bool> {
        let section = format!("remote.{name}");
        Some(self.config.as_deref()?.iter().any(|e| e.section == section))
    }

    /// The configured remote names (lowercase), `None` when unknown.
    pub fn remote_names(&self) -> Option<Vec<String>> {
        Some(
            self.config
                .as_deref()?
                .iter()
                .filter_map(|e| e.section.strip_prefix("remote."))
                .map(str::to_lowercase)
                .collect(),
        )
    }

    /// The URLs git fetches from or pushes to for repository argument
    /// `name`. `None`: the config cannot tell.
    pub fn urls(&self, name: &str, push: bool) -> Option<Vec<String>> {
        let entries = self.config.as_deref()?;
        let section = format!("remote.{name}");
        if entries
            .iter()
            .any(|e| e.section == section && e.key == "vcs")
        {
            return None;
        }
        let mut urls = Self::list(entries, name, "url")?;
        let pushurls = Self::list(entries, name, "pushurl")?;
        if urls.is_empty() {
            // Remotes in the files of git's first versions.
            let nick = !name.is_empty() && !name.contains('/') && name != "." && name != "..";
            if nick
                && ["remotes", "branches"]
                    .iter()
                    .any(|d| self.layout.common_dir.join(d).join(name).exists())
            {
                return None;
            }
            urls.push(name.to_owned());
        }
        let rewrites = |key: &str| -> Vec<(String, String)> {
            entries
                .iter()
                .filter(|e| e.key == key)
                .filter_map(|e| {
                    Some((e.section.strip_prefix("url.")?.to_owned(), e.value.clone()?))
                })
                .collect()
        };
        let instead = rewrites("insteadof");
        let rw = |u: &str, rules: &[(String, String)]| -> Option<String> {
            rules
                .iter()
                .filter(|(_, p)| u.starts_with(p.as_str()))
                .max_by_key(|(_, p)| p.len())
                .map(|(base, p)| format!("{base}{}", &u[p.len()..]))
        };
        let fetch = |u: &String| rw(u, &instead).unwrap_or_else(|| u.clone());
        if !push {
            return Some(urls.iter().map(fetch).collect());
        }
        if !pushurls.is_empty() {
            return Some(pushurls.iter().map(fetch).collect());
        }
        let push_instead = rewrites("pushinsteadof");
        // git pushes to the pushInsteadOf rewrites when one matches, else
        // to the URLs; both count.
        let mut out: Vec<String> = urls.iter().map(fetch).collect();
        out.extend(urls.iter().filter_map(|u| rw(u, &push_instead)));
        Some(out)
    }

    /// The branch `HEAD` names (`refs/heads/x`), `None` when detached or
    /// unknown.
    pub fn current(&self) -> Option<String> {
        match ref_files::head(&self.layout)? {
            Head::Symbolic(r) => Some(r),
            Head::Detached(_) => None,
        }
    }

    /// True when ref `name` may exist in this repo.
    pub fn ref_may_exist(&self, name: &str) -> bool {
        let common = &self.layout.common_dir;
        common.join("reftable").exists()
            || common.join(name).symlink_metadata().is_ok()
            || ref_files::resolve(&self.layout, name).is_some()
    }

    /// True when remote-tracking refs of a remote named `remote` may exist
    /// (`refs/remotes/<remote>/...`, loose or packed): a fetch earlier in
    /// the command can add one there.
    pub fn remote_refs_may_exist(&self, remote: &str) -> bool {
        let common = &self.layout.common_dir;
        let prefix = format!("refs/remotes/{remote}/");
        common.join("reftable").exists()
            || common.join(&prefix).symlink_metadata().is_ok()
            || match std::fs::read_to_string(common.join("packed-refs")) {
                Ok(t) => t.lines().any(|l| {
                    l.split_once(' ')
                        .is_some_and(|(_, r)| r.starts_with(&prefix))
                }),
                Err(e) => e.kind() != std::io::ErrorKind::NotFound,
            }
    }

    /// True when local path `path` may be this repo when git runs. git
    /// reads a relative path from the worktree top (the git dir of a bare
    /// repo) and tries `<p>/.git`, `<p>`, `<p>.git/.git`, `<p>.git` in
    /// that order (`enter_repo`). It is this repo when the first of those
    /// that is a git dir or gitfile is; it may be when none is (git refuses
    /// now, but the command may make one first), when a gitfile or link
    /// cannot be read, or when `changed` says the command changes the
    /// path or a dir above it.
    pub fn may_be_self(
        &self,
        path: &str,
        env: &EnvSnapshot,
        changed: &dyn Fn(&Path) -> bool,
    ) -> bool {
        let path = if path == "~" || path.starts_with("~/") {
            let Some(home) = env.get_nonempty("HOME") else {
                return true;
            };
            Path::new(home).join(path.trim_start_matches('~').trim_start_matches('/'))
        } else if path.starts_with('~') {
            return true;
        } else {
            PathBuf::from(path)
        };
        let top = self
            .layout
            .worktree
            .clone()
            .unwrap_or_else(|| self.layout.git_dir.clone());
        let base = top.join(path);
        let s = base.as_os_str().to_string_lossy();
        let s = s.trim_end_matches('/');
        for t in [
            format!("{s}/.git"),
            s.to_owned(),
            format!("{s}.git/.git"),
            format!("{s}.git"),
        ] {
            let t = PathBuf::from(t);
            if changed(&t) {
                return true;
            }
            match lookup(&t) {
                Lookup::Next => {}
                Lookup::Unknown => return true,
                Lookup::Repo(c) => return same_dir(&c, &self.layout.common_dir),
            }
        }
        true
    }
}

enum Lookup {
    /// Not a git dir or gitfile: git tries the next spelling.
    Next,
    /// A link or gitfile the guard cannot follow.
    Unknown,
    /// A repo, by its canonical common dir.
    Repo(PathBuf),
}

/// True when `a` and `b` are one dir: the same device and inode, so a
/// spelling that differs only in case on a case-insensitive file system
/// (macOS) or a bind mount still counts; the same path when the files
/// cannot be read.
fn same_dir(a: &Path, b: &Path) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(x), Ok(y)) => x.dev() == y.dev() && x.ino() == y.ino(),
        _ => true,
    }
}

/// What `enter_repo` finds at `p`.
fn lookup(p: &Path) -> Lookup {
    let md = match std::fs::metadata(p) {
        Ok(md) => md,
        Err(_) if p.symlink_metadata().is_ok() => return Lookup::Unknown,
        Err(_) => return Lookup::Next,
    };
    let git_dir = if md.is_dir() {
        if !is_git_dir(p) {
            return Lookup::Next;
        }
        p.to_owned()
    } else if md.is_file() {
        let Ok(text) = std::fs::read_to_string(p) else {
            return Lookup::Unknown;
        };
        let Some(t) = text.trim().strip_prefix("gitdir:") else {
            return Lookup::Unknown;
        };
        let t = Path::new(t.trim());
        let g = if t.is_absolute() {
            t.to_owned()
        } else {
            p.parent().unwrap_or(Path::new("/")).join(t)
        };
        if !is_git_dir(&g) {
            return Lookup::Unknown;
        }
        g
    } else {
        return Lookup::Next;
    };
    let common = match std::fs::read_to_string(git_dir.join("commondir")) {
        Ok(c) => {
            let c = Path::new(c.trim());
            if c.is_absolute() {
                c.to_owned()
            } else {
                git_dir.join(c)
            }
        }
        Err(_) => git_dir,
    };
    match std::fs::canonicalize(common) {
        Ok(c) => Lookup::Repo(c),
        Err(_) => Lookup::Unknown,
    }
}

/// How git reaches a URL.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Url {
    /// Over a network transport (ssh, http, git).
    Remote,
    /// The local path git opens.
    Local(String),
    /// A transport helper or a URL form the guard does not read.
    Unknown,
}

fn is_scheme_char(first: bool, c: char) -> bool {
    c.is_ascii_alphabetic() || (!first && (c.is_ascii_digit() || matches!(c, '+' | '-' | '.')))
}

/// git's `transport_get` and `url_is_local_not_ssh`.
pub(super) fn classify(url: &str) -> Url {
    let scheme_len = url
        .char_indices()
        .take_while(|(i, c)| is_scheme_char(*i == 0, *c))
        .count();
    let after = &url[scheme_len..];
    if scheme_len > 0 && after.starts_with("::") {
        return Url::Unknown;
    }
    if scheme_len > 0
        && let Some(rest) = after.strip_prefix("://")
    {
        let scheme = url[..scheme_len].to_ascii_lowercase();
        return match scheme.as_str() {
            "file" if rest.starts_with('/') => Url::Local(url_decode(rest)),
            "ssh" | "git" | "git+ssh" | "ssh+git" | "http" | "https" | "ftp" | "ftps" => {
                Url::Remote
            }
            _ => Url::Unknown,
        };
    }
    match (url.find(':'), url.find('/')) {
        (Some(c), Some(s)) if s < c => Url::Local(url.to_owned()),
        (Some(_), _) => Url::Remote,
        (None, _) => Url::Local(url.to_owned()),
    }
}

/// `%XX` escapes decoded, as git does for `file://` URLs.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(h) = b.get(i + 1..i + 3)
            && let Ok(h) = std::str::from_utf8(h)
            && let Ok(v) = u8::from_str_radix(h, 16)
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One refspec as git splits it: the force `+` dropped; `None` for a
/// negative refspec (`^ref`), which writes nothing.
pub(super) fn split_spec(spec: &str) -> Option<(&str, Option<&str>)> {
    let s = spec.strip_prefix('+').unwrap_or(spec);
    if s.starts_with('^') {
        return None;
    }
    Some(match s.split_once(':') {
        Some((src, dst)) => (src, Some(dst)),
        None => (s, None),
    })
}

/// The full ref a fetch writes for destination `dst` (git's
/// `get_local_ref`).
pub(super) fn fetch_dst(dst: &str) -> String {
    if dst.starts_with("refs/") {
        dst.to_owned()
    } else if ["heads/", "tags/", "remotes/"]
        .iter()
        .any(|p| dst.starts_with(p))
    {
        format!("refs/{dst}")
    } else {
        format!("refs/heads/{dst}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_classify_as_git_reads_them() {
        let l = |s: &str| Url::Local(s.to_owned());
        assert_eq!(classify("."), l("."));
        assert_eq!(classify("./"), l("./"));
        assert_eq!(classify(".git"), l(".git"));
        assert_eq!(classify("repo2"), l("repo2"));
        assert_eq!(classify("/w/repo"), l("/w/repo"));
        assert_eq!(classify("./a:b"), l("./a:b"));
        assert_eq!(classify("file:///w/%72epo"), l("/w/repo"));
        assert_eq!(classify("FILE:///w/repo"), l("/w/repo"));
        assert_eq!(classify("file://host/w/repo"), Url::Unknown);
        assert_eq!(classify("git@gitlab.com:v/r.git"), Url::Remote);
        assert_eq!(classify("host:path"), Url::Remote);
        assert_eq!(classify("ssh://h/r"), Url::Remote);
        assert_eq!(classify("https://h/r"), Url::Remote);
        assert_eq!(classify("fd::3"), Url::Unknown);
        assert_eq!(classify("foo://x"), Url::Unknown);
    }

    #[test]
    fn fetch_destinations_expand_as_git_expands_them() {
        assert_eq!(fetch_dst("main"), "refs/heads/main");
        assert_eq!(fetch_dst("heads/main"), "refs/heads/main");
        assert_eq!(fetch_dst("remotes/o/main"), "refs/remotes/o/main");
        assert_eq!(fetch_dst("refs/x"), "refs/x");
        assert_eq!(split_spec("+a:b"), Some(("a", Some("b"))));
        assert_eq!(split_spec(":b"), Some(("", Some("b"))));
        assert_eq!(split_spec("a"), Some(("a", None)));
        assert_eq!(split_spec("^a"), None);
    }

    #[test]
    fn command_config_keys_keep_the_subsection_case() {
        let e = entry("Remote.Origin.URL", Some("x")).unwrap();
        assert_eq!(
            (e.section.as_str(), e.key.as_str()),
            ("remote.Origin", "url")
        );
        let e = entry("url.git@h:a.b.insteadOf", Some("x")).unwrap();
        assert_eq!(e.section, "url.git@h:a.b");
        assert_eq!(entry("bare", None), None);
    }
}
