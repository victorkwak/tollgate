//! Remote-tracking refs confirmed with the trusted server (L2, R14, R56).
//!
//! A remote-tracking ref is a local file. `git update-ref`, `git fetch .`
//! and `git fetch <path> x:refs/remotes/origin/main` write it, and they
//! can write a fetch-like reflog line too, so neither the ref nor its
//! reflog tells where its value came from. tollgate trusts a value only
//! when the trusted server reported it for that branch: `git ls-remote
//! --heads` against the remote's fetch URL as git uses it (after
//! `insteadOf` rewrites, checked against `scope.remotes`). The query runs
//! in its own environment, with no repo and no global or system config,
//! so neither the repo's or the user's config (`remote.<name>.uploadpack`,
//! `core.sshCommand`, `url.*`) nor what the agent's shell sets for one
//! command (`GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXEC_PATH`, `PATH`)
//! changes who answers (X1).
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
use std::ffi::OsString;
use std::io::Read as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
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

/// The dirs after `job.path_prepend` on the server query's PATH.
const SYSTEM_PATH: [&str; 3] = ["/usr/local/bin", "/usr/bin", "/bin"];

/// Variables the server query keeps from tollgate's environment. None
/// changes who answers (ssh checks the host key, TLS the certificate):
/// they only reach credentials (an ssh agent, a keyring, a credential
/// helper's files).
const QUERY_PASS_THROUGH: &[&str] = &[
    "USER",
    "LOGNAME",
    "SSH_AUTH_SOCK",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
];

/// The ssh of the server query, found on its PATH. `BatchMode` fails at
/// once where ssh would ask on the terminal (unknown host key, a
/// passphrase without an agent).
const QUERY_SSH: &str = "core.sshCommand=ssh -o BatchMode=yes";

/// Where the store lives and how `ls-remote` runs.
#[derive(Debug, Clone)]
struct Site {
    file: PathBuf,
    /// A dir under the state dir that `ls-remote` runs in. git reads no
    /// repo there whatever it holds (`GIT_DIR=/dev/null`).
    neutral: PathBuf,
    /// The query's environment ([`query_env`]).
    env: BTreeMap<OsString, OsString>,
    timeout: Duration,
}

/// The server query's environment (L2, X1). Nothing in it comes from what
/// the shell that started the hook can set for one command: PATH is
/// `job.path_prepend` and then the system dirs, HOME is tollgate's home,
/// no `GIT_*` variable and no proxy variable comes through, and git reads
/// no repo (`GIT_DIR=/dev/null`), no global and no system config. So
/// `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXEC_PATH`, a fake `ssh` first on the
/// agent's PATH, and a global `core.sshCommand` or `url.<x>.insteadOf`
/// cannot pick who answers for the trusted server.
fn query_env(
    env: &EnvSnapshot,
    dirs: &Dirs,
    path_prepend: &[String],
) -> BTreeMap<OsString, OsString> {
    let path: Vec<PathBuf> = path_prepend
        .iter()
        .map(|p| dirs.expand_tilde(p))
        .chain(SYSTEM_PATH.iter().map(PathBuf::from))
        .collect();
    // The host config refuses a `:` in path_prepend (the only error).
    let path = std::env::join_paths(&path).unwrap_or_else(|_| SYSTEM_PATH.join(":").into());
    let mut vars: BTreeMap<OsString, OsString> = BTreeMap::new();
    vars.insert("PATH".into(), path);
    vars.insert("HOME".into(), dirs.home().as_os_str().to_owned());
    for key in QUERY_PASS_THROUGH {
        if let Some(v) = env.get_nonempty(key) {
            vars.insert((*key).into(), v.to_owned());
        }
    }
    for (k, v) in [
        ("LC_ALL", "C"),
        ("GIT_DIR", "/dev/null"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
        ("GIT_CONFIG_GLOBAL", "/dev/null"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ] {
        vars.insert(k.into(), v.into());
    }
    vars
}

/// The `global` and `system` entries of `git config -z --show-scope`
/// output (`scope\0key\nvalue\0`; a key with no value, `key\0`, is a
/// boolean true), in order.
fn user_entries(out: &[u8]) -> Vec<(String, String)> {
    let mut fields = out.split(|b| *b == 0);
    let mut entries = Vec::new();
    while let (Some(scope), Some(entry)) = (fields.next(), fields.next()) {
        if !matches!(scope, b"global" | b"system") {
            continue;
        }
        let entry = String::from_utf8_lossy(entry);
        let (key, value) = entry.split_once('\n').unwrap_or((&entry, "true"));
        entries.push((key.to_owned(), value.to_owned()));
    }
    entries
}

impl Site {
    /// The user's `credential.*` settings from the global and system
    /// config, in order. A credential helper only supplies credentials; it
    /// cannot change which server answers, so the query keeps them (an
    /// https remote with a helper keeps working).
    fn user_credentials(&self) -> Vec<(String, String)> {
        let out = Command::new(crate::gitx::program())
            .env_clear()
            .envs(self.env.iter().filter(|(k, _)| {
                !matches!(
                    k.to_str(),
                    Some("GIT_CONFIG_NOSYSTEM" | "GIT_CONFIG_GLOBAL")
                )
            }))
            .arg("-C")
            .arg(&self.neutral)
            .args([
                "config",
                "-z",
                "--show-scope",
                "--get-regexp",
                r"^credential\.",
            ])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output();
        out.map(|o| user_entries(&o.stdout)).unwrap_or_default()
    }

    /// `git <args>` as the server query runs it: in the neutral dir, with
    /// [`query_env`], the user's credential settings and [`QUERY_SSH`].
    fn query_command(&self, args: &[&str]) -> Result<Command, String> {
        fsx::ensure_dir(&self.neutral).map_err(|e| format!("{}: {e}", self.neutral.display()))?;
        let mut cmd = Command::new(crate::gitx::program());
        cmd.env_clear().envs(&self.env);
        let creds = self.user_credentials();
        if !creds.is_empty() {
            cmd.env("GIT_CONFIG_COUNT", creds.len().to_string());
            for (i, (k, v)) in creds.iter().enumerate() {
                cmd.env(format!("GIT_CONFIG_KEY_{i}"), k)
                    .env(format!("GIT_CONFIG_VALUE_{i}"), v);
            }
        }
        cmd.arg("-C")
            .arg(&self.neutral)
            .args(["-c", QUERY_SSH])
            .args(args)
            .stdin(Stdio::null());
        Ok(cmd)
    }
}

/// The trusted remotes of a repo and what their server reported.
#[derive(Debug)]
pub struct RemoteRefs {
    remotes: Vec<TrustedRemote>,
    /// The record of the repo's trusted remotes (item 33).
    record: Option<crate::remote_record::Checked>,
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
            record: None,
            site: None,
            store: Mutex::new(None),
            asked: Mutex::new(BTreeMap::new()),
        }
    }

    /// `remotes`, with the store in `dirs`. `ls-remote` runs in its own
    /// environment ([`query_env`]): from `env` it takes only what reaches
    /// credentials, and it finds git and ssh on `path_prepend` (the host's
    /// `job.path_prepend`) and then the system dirs.
    #[must_use]
    pub fn new(
        dirs: &Dirs,
        env: &EnvSnapshot,
        path_prepend: &[String],
        remotes: Vec<TrustedRemote>,
    ) -> Self {
        let state = dirs.state_dir();
        Self {
            remotes,
            record: None,
            site: Some(Site {
                file: dirs.remote_refs_file(),
                neutral: state.join("neutral"),
                env: query_env(env, dirs, path_prepend),
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

    /// Item 33: checks and updates the record of the trusted remotes of
    /// the repo of `layout`, read through `git` ([`crate::remote_record`]).
    #[must_use]
    pub fn with_record(mut self, dirs: &Dirs, git: &Git, layout: &crate::gitx::RepoLayout) -> Self {
        self.record = Some(crate::remote_record::check(
            dirs,
            git,
            &layout.repo_key(),
            &layout.repo_dir(),
            &self.remotes,
        ));
        self
    }

    /// Item 33: why the policy must deny (no anchor, never local refs):
    /// a recorded trusted remote is gone, or the record is unusable.
    #[must_use]
    pub fn record_denial(&self) -> Option<String> {
        self.record.as_ref()?.deny_message()
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

/// `git ls-remote --heads -- <url>` as the server query runs it
/// ([`Site::query_command`]), with a time limit.
fn ls_remote_heads(site: &Site, url: &str) -> Result<Heads, String> {
    let mut cmd = site.query_command(&["ls-remote", "--heads", "--", url])?;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
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

    /// X1: the server query gets nothing from the shell that started the
    /// hook that can change who answers (`GIT_SSH*`, `GIT_PROXY_COMMAND`,
    /// `GIT_EXEC_PATH`, `GIT_CONFIG_*`, proxies, the agent's PATH), reads
    /// no repo, global or system config, and keeps only the user's
    /// `credential.*` settings, which cannot change the server.
    #[test]
    fn the_server_query_ignores_the_shell_and_the_user_git_config_x1() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[core]\n\tsshCommand = /tmp/forger\n\tgitProxy = /tmp/proxy\n[ssh]\n\tvariant = simple\n[url \"/fake\"]\n\tinsteadOf = /trusted\n[http]\n\tproxy = http://proxy.invalid\n[credential]\n\thelper =\n\thelper = store\n[credential \"https://h.invalid/a=b\"]\n\tusername = me\n\tuseHttpPath\n",
        )
        .unwrap();
        let env = EnvSnapshot::from_pairs([
            ("PATH", OsString::from("/agent/bin:/usr/bin")),
            ("HOME", home.clone().into_os_string()),
            ("XDG_STATE_HOME", root.join("state").into_os_string()),
            ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
            ("GIT_SSH_COMMAND", "/tmp/forger".into()),
            ("GIT_SSH", "/tmp/forger".into()),
            ("GIT_SSH_VARIANT", "simple".into()),
            ("GIT_PROXY_COMMAND", "/tmp/proxy".into()),
            ("GIT_EXEC_PATH", "/tmp/exec".into()),
            ("GIT_ASKPASS", "/tmp/askpass".into()),
            (
                "GIT_CONFIG_PARAMETERS",
                "'url./fake2.insteadof'='/trusted'".into(),
            ),
            ("GIT_CONFIG_COUNT", "1".into()),
            ("GIT_CONFIG_KEY_0", "core.sshCommand".into()),
            ("GIT_CONFIG_VALUE_0", "/tmp/forger".into()),
            ("https_proxy", "http://proxy.invalid".into()),
            ("SSH_AUTH_SOCK", "/run/agent.sock".into()),
        ]);
        let dirs = Dirs::from_env(&env).unwrap();
        let refs = RemoteRefs::new(&dirs, &env, &["~/tools".to_owned()], Vec::new());
        let site = refs.site.as_ref().unwrap();
        // A repo planted at the dir the query runs in.
        std::fs::create_dir_all(&site.neutral).unwrap();
        let plant = |args: &[&str]| {
            let st = std::process::Command::new("git")
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .arg("-C")
                .arg(&site.neutral)
                .args(args)
                .status()
                .unwrap();
            assert!(st.success(), "{args:?}");
        };
        plant(&["init", "-q"]);
        plant(&["config", "url./fake3.insteadOf", "/trusted"]);
        plant(&["config", "core.sshCommand", "/tmp/forger"]);

        let out = site
            .query_command(&["config", "--list", "--show-scope"])
            .unwrap()
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert_eq!(
            text.lines().collect::<Vec<_>>(),
            [
                "command\tcredential.helper=",
                "command\tcredential.helper=store",
                "command\tcredential.https://h.invalid/a=b.username=me",
                "command\tcredential.https://h.invalid/a=b.usehttppath=true",
                "command\tcore.sshcommand=ssh -o BatchMode=yes",
            ],
            "{text}"
        );

        // What a program git starts (ssh, a credential helper) sees.
        let out = site
            .query_command(&["-c", "alias.show-env=!env", "show-env"])
            .unwrap()
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        let var = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .map(str::to_owned)
        };
        for gone in [
            "GIT_SSH_COMMAND",
            "GIT_SSH",
            "GIT_SSH_VARIANT",
            "GIT_PROXY_COMMAND",
            "GIT_ASKPASS",
            "https_proxy",
        ] {
            assert_eq!(var(gone), None, "{gone}: {text}");
        }
        // git sets GIT_EXEC_PATH for its children: its own, never ours.
        for planted in ["fake2", "/tmp/forger", "/tmp/exec", "/tmp/proxy"] {
            assert!(!text.contains(planted), "{planted}: {text}");
        }
        let path = var("PATH").unwrap();
        assert!(
            !path.contains("/agent/bin")
                && path.ends_with(&format!(
                    "{}:/usr/local/bin:/usr/bin:/bin",
                    home.join("tools").display()
                )),
            "{path}"
        );
        assert_eq!(var("HOME"), Some(home.display().to_string()));
        assert_eq!(var("SSH_AUTH_SOCK").as_deref(), Some("/run/agent.sock"));
        assert_eq!(var("GIT_CONFIG_GLOBAL").as_deref(), Some("/dev/null"));
        assert_eq!(var("GIT_CONFIG_NOSYSTEM").as_deref(), Some("1"));
        assert_eq!(var("GIT_TERMINAL_PROMPT").as_deref(), Some("0"));
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
