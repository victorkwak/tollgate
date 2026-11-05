//! Remote-tracking refs confirmed with the trusted server (L2, R14, R56).
//!
//! A remote-tracking ref is a local file. `git update-ref`, `git fetch .`
//! and `git fetch <path> x:refs/remotes/origin/main` write it, and they
//! can write a fetch-like reflog line too, so neither the ref nor its
//! reflog tells where its value came from. tollgate trusts a value only
//! when the trusted server reported it for that branch: `git ls-remote
//! --heads` against the remote's fetch URL as git uses it (after
//! `insteadOf` rewrites, checked against `scope.remotes`), run outside the
//! repo, so no repo config (`remote.<name>.uploadpack`, `core.sshCommand`,
//! `url.*`) changes where it goes.
//!
//! Each answer is kept in `<state>/remote-refs.json` per URL (the newest
//! values of each branch, newest first). A value the server reported once
//! stays usable after the server moves on, so a clone that has not
//! fetched for a while needs no network, and the server is asked again
//! only when a remote-tracking ref holds a value it never reported (a
//! fetch moved it, or someone forged it). Where a value decides the
//! policy (L2 anchors), the newest reported value present in the repo
//! counts, never an older one the tracking ref was moved back to.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::fsx;
use crate::gitx::{Git, GitError, Oid};

/// How long one `git ls-remote` may take: an unreachable server must not
/// hold a hook until the Bash timeout.
pub const LS_REMOTE_TIMEOUT: Duration = Duration::from_secs(20);

/// Reported values kept per branch, newest first.
const KEEP_PER_REF: usize = 16;

/// Branches kept per URL; above it, those the last answer lacks go.
const KEEP_REFS: usize = 1024;

/// A local tracking value that is reported but not the newest asks the
/// server again only after this long (another clone of the same URL may
/// have fetched further).
const REASK_AFTER: Duration = Duration::from_secs(600);

const STORE_VERSION: u32 = 1;

/// `refs/heads/<branch>` -> value, as one `ls-remote --heads` answered.
pub type Heads = BTreeMap<String, Oid>;

/// A remote whose fetch URL, as git uses it, matches `scope.remotes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedRemote {
    /// Remote name.
    pub name: String,
    /// The fetch URL git uses (after rewrites).
    pub url: String,
}

/// What the server reported for one URL.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct UrlEntry {
    /// When the server last answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    asked: Option<jiff::Timestamp>,
    /// `refs/heads/<branch>` -> reported values, newest first.
    #[serde(default)]
    refs: BTreeMap<String, Vec<Oid>>,
}

/// `<state>/remote-refs.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Store {
    version: u32,
    #[serde(default)]
    urls: BTreeMap<String, UrlEntry>,
}

impl Store {
    fn merge(&mut self, url: &str, heads: &Heads, now: jiff::Timestamp) {
        let e = self.urls.entry(url.to_owned()).or_default();
        e.asked = Some(now);
        for (r, oid) in heads {
            let list = e.refs.entry(r.clone()).or_default();
            list.retain(|o| o != oid);
            list.insert(0, oid.clone());
            list.truncate(KEEP_PER_REF);
        }
        if e.refs.len() > KEEP_REFS {
            e.refs.retain(|r, _| heads.contains_key(r));
        }
    }
}

/// Where the store lives and how `ls-remote` runs.
#[derive(Debug, Clone)]
struct Site {
    file: PathBuf,
    /// An empty dir under the state dir: `ls-remote` runs there, with
    /// `GIT_CEILING_DIRECTORIES` at its parent, so it finds no repo.
    neutral: PathBuf,
    env: EnvSnapshot,
    timeout: Duration,
}

/// The trusted remotes of a repo and what their server reported.
#[derive(Debug)]
pub struct RemoteRefs {
    remotes: Vec<TrustedRemote>,
    site: Option<Site>,
    /// The store as last read or written.
    store: Mutex<Option<Store>>,
    /// URLs asked in this process, with the outcome.
    asked: Mutex<BTreeMap<String, Result<Heads, String>>>,
}

impl RemoteRefs {
    /// No trusted remote.
    #[must_use]
    pub fn none() -> Self {
        Self {
            remotes: Vec::new(),
            site: None,
            store: Mutex::new(None),
            asked: Mutex::new(BTreeMap::new()),
        }
    }

    /// `remotes`, with the store in `dirs` and `ls-remote` in `env`.
    #[must_use]
    pub fn new(dirs: &Dirs, env: &EnvSnapshot, remotes: Vec<TrustedRemote>) -> Self {
        let state = dirs.state_dir();
        Self {
            remotes,
            site: Some(Site {
                file: dirs.remote_refs_file(),
                neutral: state.join("neutral"),
                env: env.clone(),
                timeout: LS_REMOTE_TIMEOUT,
            }),
            store: Mutex::new(None),
            asked: Mutex::new(BTreeMap::new()),
        }
    }

    /// True when no remote is trusted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remotes.is_empty()
    }

    /// The trusted remotes, in config order.
    #[must_use]
    pub fn remotes(&self) -> &[TrustedRemote] {
        &self.remotes
    }

    /// The trusted remote named `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&TrustedRemote> {
        self.remotes.iter().find(|r| r.name == name)
    }

    fn read_store(&self) -> Store {
        let Some(site) = &self.site else {
            return Store::default();
        };
        fsx::read_optional(&site.file)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<Store>(&b).ok())
            .filter(|s| s.version == STORE_VERSION)
            .unwrap_or_default()
    }

    /// The store, read once.
    fn with_store<T>(&self, f: impl FnOnce(&Store) -> T) -> T {
        let mut guard = self.store.lock().unwrap_or_else(|p| p.into_inner());
        let store = guard.get_or_insert_with(|| self.read_store());
        f(store)
    }

    /// Values the server reported for `refs/heads/<branch>`, newest first.
    fn reported(&self, url: &str, branch: &str) -> Vec<Oid> {
        let refname = format!("refs/heads/{branch}");
        self.with_store(|s| {
            s.urls
                .get(url)
                .and_then(|e| e.refs.get(&refname))
                .cloned()
                .unwrap_or_default()
        })
    }

    /// When the server of `url` last answered.
    fn last_asked(&self, url: &str) -> Option<jiff::Timestamp> {
        self.with_store(|s| s.urls.get(url).and_then(|e| e.asked))
    }

    /// The server's branches now (`git ls-remote --heads`), asked at most
    /// once per process and URL; each answer goes into the store.
    pub fn server_heads(&self, remote: &TrustedRemote) -> Result<Heads, String> {
        let mut asked = self.asked.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(a) = asked.get(&remote.url) {
            return a.clone();
        }
        let Some(site) = &self.site else {
            return Err("no state dir to keep the answer".into());
        };
        let answer = ls_remote_heads(site, &remote.url);
        if let Ok(heads) = &answer {
            let now = jiff::Timestamp::now();
            // Merge into the file as it is now: other hooks write it too.
            let mut fresh = self.read_store();
            fresh.version = STORE_VERSION;
            fresh.merge(&remote.url, heads, now);
            if let Ok(json) = serde_json::to_vec(&fresh) {
                let _ = fsx::ensure_dir(site.file.parent().unwrap_or(&site.neutral))
                    .and_then(|()| fsx::write_atomic(&site.file, &json));
            }
            *self.store.lock().unwrap_or_else(|p| p.into_inner()) = Some(fresh);
        }
        asked.insert(remote.url.clone(), answer.clone());
        answer
    }

    /// L2: the anchor commit for `refs/remotes/<remote>/<branch>`, whose
    /// local value is `local`: the newest value the server reported for the
    /// branch that this repo has, or why there is none. The server is asked
    /// when `local` is a value it never reported, or a reported but older
    /// one and the last answer is older than [`REASK_AFTER`].
    pub fn anchor_tip(
        &self,
        git: &Git,
        remote: &TrustedRemote,
        branch: &str,
        local: &Oid,
    ) -> Result<Result<Oid, String>, GitError> {
        let known = self.reported(&remote.url, branch);
        let stale = self.last_asked(&remote.url).is_none_or(|t| {
            jiff::Timestamp::now()
                .duration_since(t)
                .unsigned_abs()
                .ge(&REASK_AFTER)
        });
        let ask = !known.contains(local) || (known.first() != Some(local) && stale);
        let asked = ask.then(|| self.server_heads(remote));
        for oid in self.reported(&remote.url, branch) {
            if git
                .rev_parse_verify(&format!("{oid}^{{commit}}"))?
                .is_some()
            {
                return Ok(Ok(oid));
            }
        }
        Ok(Err(match asked {
            Some(Err(e)) => format!("git ls-remote {} failed: {e}", remote.url),
            Some(Ok(heads)) if !heads.contains_key(&format!("refs/heads/{branch}")) => {
                format!("{} has no branch {branch}", remote.url)
            }
            _ => format!(
                "the value {} reports for {branch} is not in this repo",
                remote.url
            ),
        }))
    }

    /// R56: true when `oid` is a value the server reported for
    /// `refs/heads/<branch>` (asking once when it is not known yet).
    pub fn is_reported(&self, remote: &TrustedRemote, branch: &str, oid: &Oid) -> bool {
        if self.reported(&remote.url, branch).contains(oid) {
            return true;
        }
        if self.server_heads(remote).is_err() {
            return false;
        }
        self.reported(&remote.url, branch).contains(oid)
    }

    /// The trusted remote and branch of `refs/remotes/<remote>/<branch>`;
    /// the longest remote name wins when names nest (`a` and `a/b`).
    #[must_use]
    pub fn split_tracking<'r>(&self, refname: &'r str) -> Option<(&TrustedRemote, &'r str)> {
        let rest = refname.strip_prefix("refs/remotes/")?;
        self.remotes
            .iter()
            .filter_map(|r| {
                rest.strip_prefix(r.name.as_str())
                    .and_then(|b| b.strip_prefix('/'))
                    .filter(|b| !b.is_empty())
                    .map(|b| (r, b))
            })
            .max_by_key(|(r, _)| r.name.len())
    }
}

/// `git ls-remote --heads -- <url>` in the neutral dir with a time limit.
fn ls_remote_heads(site: &Site, url: &str) -> Result<Heads, String> {
    fsx::ensure_dir(&site.neutral).map_err(|e| format!("{}: {e}", site.neutral.display()))?;
    let git = Git::scrubbed(&site.env, &site.neutral);
    let mut cmd = git.command(["ls-remote", "--heads", "--", url]);
    if let Some(parent) = site.neutral.parent() {
        cmd.env("GIT_CEILING_DIRECTORIES", parent);
    }
    let mut child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run git: {e}"))?;
    let (mut out, mut err) = (child.stdout.take(), child.stderr.take());
    let (stdout, stderr, status) = std::thread::scope(|s| {
        let o = s.spawn(move || {
            let mut b = Vec::new();
            if let Some(o) = out.as_mut() {
                let _ = o.read_to_end(&mut b);
            }
            b
        });
        let e = s.spawn(move || {
            let mut b = Vec::new();
            if let Some(e) = err.as_mut() {
                let _ = e.take(8192).read_to_end(&mut b);
            }
            b
        });
        let end = Instant::now() + site.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(10)),
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        (
            o.join().unwrap_or_default(),
            e.join().unwrap_or_default(),
            status,
        )
    });
    let Some(status) = status else {
        return Err(format!("no answer in {}s", site.timeout.as_secs()));
    };
    if !status.success() {
        let msg = String::from_utf8_lossy(&stderr);
        return Err(msg
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("failed")
            .trim()
            .to_owned());
    }
    let mut heads = BTreeMap::new();
    for line in String::from_utf8_lossy(&stdout).lines() {
        let Some((oid, name)) = line.split_once('\t') else {
            continue;
        };
        if let (Ok(oid), true) = (Oid::parse(oid), name.starts_with("refs/heads/")) {
            heads.insert(name.to_owned(), oid);
        }
    }
    Ok(heads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(c: char) -> Oid {
        Oid::parse(&c.to_string().repeat(40)).unwrap()
    }

    #[test]
    fn answers_keep_the_newest_values_first_l2() {
        let mut s = Store::default();
        let now = jiff::Timestamp::now();
        let heads = |o: char| BTreeMap::from([("refs/heads/main".to_owned(), oid(o))]);
        s.merge("u", &heads('a'), now);
        s.merge("u", &heads('b'), now);
        s.merge("u", &heads('a'), now);
        assert_eq!(s.urls["u"].refs["refs/heads/main"], [oid('a'), oid('b')]);
        for c in "0123456789abcdef".chars() {
            s.merge("u", &heads(c), now);
        }
        assert_eq!(s.urls["u"].refs["refs/heads/main"].len(), KEEP_PER_REF);
        assert_eq!(s.urls["u"].refs["refs/heads/main"][0], oid('f'));
    }

    #[test]
    fn tracking_refs_split_by_the_longest_remote_name() {
        let r = RemoteRefs {
            remotes: vec![
                TrustedRemote {
                    name: "a".into(),
                    url: "u1".into(),
                },
                TrustedRemote {
                    name: "a/b".into(),
                    url: "u2".into(),
                },
            ],
            ..RemoteRefs::none()
        };
        let (rem, b) = r.split_tracking("refs/remotes/a/b/main").unwrap();
        assert_eq!((rem.name.as_str(), b), ("a/b", "main"));
        let (rem, b) = r.split_tracking("refs/remotes/a/x/y").unwrap();
        assert_eq!((rem.name.as_str(), b), ("a", "x/y"));
        assert!(r.split_tracking("refs/remotes/ab/main").is_none());
        assert!(r.split_tracking("refs/heads/main").is_none());
    }
}
