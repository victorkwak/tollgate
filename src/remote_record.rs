//! Which trusted remotes each repo had (item 33, R4, L2; secreview notes 2
//! and 3).
//!
//! With no trusted remote, the policy anchor falls back to the local full
//! refs (L2), which anything in the repo can move. So once a repo had a
//! trusted remote, losing it must not make that fallback: a script that
//! removes `origin`, or points it at another repo, would otherwise choose
//! the policy that checks its own commits.
//!
//! `<state>/trusted-remotes/<repo key>.json` lists each remote that was
//! trusted in the repo: its name then, its fetch URL as git used it, and
//! when it was first seen. The URL is stored as git used it and compared
//! by [`url_identity`], computed when read, so a change of the URL parser
//! applies to old records too and never makes them read as lost. A remote
//! is lost when no trusted remote of the repo has a URL with its identity
//! now (removed, set to another URL, or no longer trusted by
//! `scope.remotes`); a rename keeps the URL and is not a loss.
//!
//! The repo key is the realpath of the common dir, which a copy or a move
//! changes. So the record also holds the root commits of the repo (of its
//! trusted remotes' tracking refs and `HEAD` when first recorded), and
//! `<state>/trusted-remotes/index.json` lists, append-only, every repo key
//! that had a record with those commits. A repo with no recorded remote
//! (no record yet, or one that `tollgate remotes forget` emptied) that has
//! a commit of another indexed repo is a copy, a move or a clone of it:
//! it takes over that repo's recorded remotes, so removing the remote in
//! the new path is a loss too. A key the index lists whose record is gone
//! is unusable, never "no record". A missing index is unusable too
//! (secreview note 27): `tollgate install` makes it once, and only
//! `tollgate remotes forget` makes it again, from the records left.
//!
//! A lost remote, or a record or index that cannot be read, parsed or
//! written, denies (no policy anchor) and keeps the repo in scope: this
//! is fail closed. Victor accepts the change with `tollgate remotes
//! forget` at a terminal, which empties the record (a tombstone, not a
//! removal): the remotes it held, and the repos whose commits this one
//! had then, are not taken over again; the next gated command records
//! the trusted remotes the repo has then.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::trust::url_identity;
use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::{Git, Oid};
use crate::ids::RepoKey;
use crate::locks::LockFile;
use crate::remote_refs::TrustedRemote;

/// Version 2 adds `forgotten`, `forgot_repos` and `commits`; a version 1
/// record reads with them empty.
const VERSION: u32 = 2;
const LEGACY_VERSION: u32 = 1;
const INDEX_VERSION: u32 = 1;

/// Commits kept per repo to tell copies of it: its root commits (most
/// repos have one), few enough for one `cat-file` of every indexed repo
/// on each `Gate::open` of a repo with no recorded remote (L19: a missing
/// id costs git a pack rescan, 15 us).
const MAX_COMMITS: usize = 8;

/// How long a writer waits for another writer of the same record. Writes
/// take milliseconds; a lock held longer (a process that holds it on
/// purpose) denies instead of hanging the hook.
const LOCK_WAIT: Duration = Duration::from_secs(2);

/// A remote seen trusted in one repo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeenRemote {
    /// Its name then.
    pub name: String,
    /// Its fetch URL as git used it.
    pub url: String,
    /// When it was first seen trusted.
    pub since: jiff::Timestamp,
    /// The repo it was recorded in, when that is another repo whose
    /// commits this one has (a copy, a move or a clone of it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
}

impl SeenRemote {
    fn describe(&self) -> String {
        match &self.from {
            Some(dir) => format!(
                "{} ({}, recorded in {dir}, whose commits this repo has)",
                self.name, self.url
            ),
            None => format!("{} ({})", self.name, self.url),
        }
    }
}

/// The record of one repo.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Record {
    /// Remotes trusted in the repo, or in a repo it is a copy of.
    pub remotes: Vec<SeenRemote>,
    /// Remotes `tollgate remotes forget` accepted as gone; not taken over
    /// from another repo again.
    pub forgotten: Vec<SeenRemote>,
    /// Keys of the repos whose commits this one had when `forget` ran;
    /// their remotes are not taken over again.
    pub forgot_repos: Vec<RepoKey>,
    /// Commits of the repo, to tell its copies.
    pub commits: Vec<Oid>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordFile {
    version: u32,
    remotes: Vec<SeenRemote>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    forgotten: Vec<SeenRemote>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    forgot_repos: Vec<RepoKey>,
    #[serde(default)]
    commits: Vec<Oid>,
}

/// One repo in the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexEntry {
    /// The repo's dir when first indexed.
    pub dir: String,
    /// Its commits, as its record holds them.
    pub commits: Vec<Oid>,
}

/// Every repo key that ever had a record (append-only).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Index {
    version: u32,
    /// By repo key.
    pub repos: BTreeMap<RepoKey, IndexEntry>,
}

/// What the record says about the repo now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    /// Every recorded remote is still trusted.
    Kept,
    /// These recorded remotes are gone.
    Lost(Vec<SeenRemote>),
    /// The record cannot be read, parsed or written (why).
    Broken(String),
}

/// The record of one repo, checked against its trusted remotes now.
#[derive(Debug, Clone)]
pub struct Checked {
    /// The record file.
    pub file: PathBuf,
    /// What it says.
    pub status: Status,
}

impl Checked {
    /// Why the policy must deny (no anchor), or `None`.
    #[must_use]
    pub fn deny_message(&self) -> Option<String> {
        let file = self.file.display();
        match &self.status {
            Status::Kept => None,
            Status::Lost(lost) => {
                let all: Vec<String> = lost.iter().map(SeenRemote::describe).collect();
                let first = &lost[0];
                Some(format!(
                    "no policy anchor (L2, item 33): this repo had the trusted remote {} and no trusted remote has that URL now, so the policy anchor would fall back to local refs; put it back (git remote add {} {}, or git remote set-url {} {}), or, to accept the change, run tollgate remotes forget in this repo from your own terminal (record: {file})",
                    all.join(", "),
                    first.name,
                    first.url,
                    first.name,
                    first.url,
                ))
            }
            Status::Broken(why) if why.contains(INDEX_FIX) || why.contains(INDEX_MISSING_FIX) => {
                Some(format!(
                    "no policy anchor (L2, item 33): {why}; until then a lost trusted remote cannot be told apart"
                ))
            }
            Status::Broken(why) => Some(format!(
                "no policy anchor (L2, item 33): the record of this repo's trusted remotes is unusable ({why}), so a lost trusted remote cannot be told apart; run tollgate remotes forget in this repo from your own terminal to start a new record (record: {file})"
            )),
        }
    }

    /// True when the policy must deny.
    #[must_use]
    pub fn denies(&self) -> bool {
        self.status != Status::Kept
    }
}

/// What the record check asks the repo's object store.
pub trait Objects {
    /// Of `commits`, those that are commits in the repo.
    fn present(&self, commits: &[Oid]) -> Result<BTreeSet<Oid>, String>;
    /// Commits that tell the repo: the root commits of the tracking refs
    /// of `trusted` and of `HEAD`.
    fn identity(&self, trusted: &[TrustedRemote]) -> Result<Vec<Oid>, String>;
}

impl Objects for Git {
    fn present(&self, commits: &[Oid]) -> Result<BTreeSet<Oid>, String> {
        if commits.is_empty() {
            return Ok(BTreeSet::new());
        }
        // Each id as written, never a replacement (`refs/replace`), and no
        // fetch from a promisor remote for a missing one.
        let mut cmd = self.command([
            "--no-replace-objects",
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
        ]);
        cmd.env("GIT_NO_LAZY_FETCH", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("cannot run git: {e}"))?;
        let input: String = commits.iter().map(|c| format!("{c}\n")).collect();
        let mut stdin = child.stdin.take();
        let out = std::thread::scope(|s| {
            s.spawn(move || {
                if let Some(mut w) = stdin.take() {
                    let _ = w.write_all(input.as_bytes());
                }
            });
            child.wait_with_output()
        })
        .map_err(|e| format!("git cat-file: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git cat-file failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = text.lines().collect();
        if lines.len() != commits.len() {
            return Err(format!(
                "git cat-file answered {} lines for {} ids",
                lines.len(),
                commits.len()
            ));
        }
        Ok(commits
            .iter()
            .zip(lines)
            .filter(|(c, l)| *l == format!("{c} commit"))
            .map(|(c, _)| c.clone())
            .collect())
    }

    fn identity(&self, trusted: &[TrustedRemote]) -> Result<Vec<Oid>, String> {
        let mut out = Vec::new();
        if !trusted.is_empty() {
            let mut args = vec![
                "for-each-ref".to_owned(),
                "--format=%(objectname) %(objecttype)".to_owned(),
            ];
            args.extend(trusted.iter().map(|t| format!("refs/remotes/{}/", t.name)));
            let text = self.run(&args).map_err(|e| e.to_string())?;
            for line in String::from_utf8_lossy(&text).lines() {
                if let Some(oid) = line.strip_suffix(" commit")
                    && let Ok(oid) = Oid::parse(oid)
                {
                    out.push(oid);
                }
            }
        }
        if let Some(head) = self
            .rev_parse_verify("HEAD^{commit}")
            .map_err(|e| e.to_string())?
        {
            out.push(head);
        }
        if out.is_empty() {
            return Ok(out);
        }
        // Their root commits: one or a few per repo, and in every copy and
        // clone that has any of the history (a shallow clone's boundary
        // reads as a root). One walk, when the record starts or gains a
        // remote (6 ms for 5000 commits with a commit-graph).
        let mut args = vec![
            "--no-replace-objects".to_owned(),
            "rev-list".to_owned(),
            "--max-parents=0".to_owned(),
        ];
        args.extend(out.iter().map(ToString::to_string));
        let text = self.run(&args).map_err(|e| e.to_string())?;
        let mut roots: Vec<Oid> = String::from_utf8_lossy(&text)
            .lines()
            .filter_map(|l| Oid::parse(l).ok())
            .collect();
        roots.sort();
        roots.dedup();
        Ok(roots)
    }
}

/// `<state>/trusted-remotes`.
fn records_dir(dirs: &Dirs) -> PathBuf {
    dirs.state_dir().join("trusted-remotes")
}

/// `<state>/trusted-remotes/<repo key>.json`.
#[must_use]
pub fn file(dirs: &Dirs, repo: &RepoKey) -> PathBuf {
    record_in(&records_dir(dirs), repo)
}

fn record_in(dir: &Path, repo: &RepoKey) -> PathBuf {
    dir.join(format!("{}.json", repo.as_str()))
}

/// `<state>/trusted-remotes/index.json` (a repo key is 16 hex, so no
/// record has this name).
fn index_in(dir: &Path) -> PathBuf {
    dir.join("index.json")
}

fn lock_path(file: &Path) -> PathBuf {
    file.with_extension("lock")
}

/// The record; `None` when there is none.
pub fn read(file: &Path) -> Result<Option<Record>, String> {
    let Some(bytes) = fsx::read_optional(file).map_err(|e| format!("cannot read it: {e}"))? else {
        return Ok(None);
    };
    let r: RecordFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("cannot parse it: {e}"))?;
    if r.version != VERSION && r.version != LEGACY_VERSION {
        return Err(format!("unknown version {}", r.version));
    }
    Ok(Some(Record {
        remotes: r.remotes,
        forgotten: r.forgotten,
        forgot_repos: r.forgot_repos,
        commits: r.commits,
    }))
}

fn write(file: &Path, r: &Record) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(&RecordFile {
        version: VERSION,
        remotes: r.remotes.clone(),
        forgotten: r.forgotten.clone(),
        forgot_repos: r.forgot_repos.clone(),
        commits: r.commits.clone(),
    })
    .map_err(|e| format!("cannot write it: {e}"))?;
    fsx::write_atomic(file, &json).map_err(|e| format!("cannot write it: {e}"))
}

/// An unusable index is not for `forget` of one repo to replace: it is
/// what tells every repo that had trusted remotes.
const INDEX_FIX: &str = "it lists every repo that had trusted remotes; repair it, or remove it and run tollgate remotes forget in a repo, from your own terminal";

/// A missing index is never "no repo had trusted remotes" (secreview
/// note 27): deleting it with a record would make that record's repo
/// read as new. `tollgate install` makes it once; after that only
/// `tollgate remotes forget` starts a new one, from the records left.
const INDEX_MISSING_FIX: &str = "without it a deleted record cannot be told from none; to start a new index from the records left, run tollgate remotes forget in a repo from your own terminal";

/// The index; `None` when there is none.
fn load_index(file: &Path) -> Result<Option<Index>, String> {
    let shown = file.display();
    let Some(bytes) = fsx::read_optional(file)
        .map_err(|e| format!("cannot read the index {shown}: {e}; {INDEX_FIX}"))?
    else {
        return Ok(None);
    };
    let i: Index = serde_json::from_slice(&bytes)
        .map_err(|e| format!("cannot parse the index {shown}: {e}; {INDEX_FIX}"))?;
    if i.version != INDEX_VERSION {
        return Err(format!(
            "the index {shown} has unknown version {}; {INDEX_FIX}",
            i.version
        ));
    }
    Ok(Some(i))
}

/// The index; a missing one is unusable.
fn read_index(file: &Path) -> Result<Index, String> {
    load_index(file)?.ok_or_else(|| {
        format!(
            "the index {} is missing; it lists every repo that had trusted remotes, and {INDEX_MISSING_FIX}",
            file.display()
        )
    })
}

/// A new index from the records in `dir`: every `<repo key>.json` with
/// the commits it holds. A record that cannot be read is listed with no
/// commits, so its repo still denies.
fn rebuild_index(dir: &Path) -> Result<Index, String> {
    let mut repos = BTreeMap::new();
    let entries = match std::fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("cannot list {}: {e}", dir.display())),
        Ok(it) => it
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("cannot list {}: {e}", dir.display()))?,
    };
    for e in entries {
        let name = e.file_name();
        let Some(key) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|k| RepoKey::parse(k).ok())
        else {
            continue;
        };
        let path = e.path();
        let commits = read(&path)
            .ok()
            .flatten()
            .map(|r| r.commits)
            .unwrap_or_default();
        repos.insert(
            key,
            IndexEntry {
                dir: format!("the repo of the record {}", path.display()),
                commits,
            },
        );
    }
    Ok(Index {
        version: INDEX_VERSION,
        repos,
    })
}

/// What [`ensure_index`] found or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexSetup {
    /// The index is there (usable or not: a check reads it).
    Present,
    /// It was missing and is made now from this many records.
    Created(usize),
    /// It is missing and `may_create` was false.
    Missing(PathBuf),
}

/// `tollgate install` (and the bench, for its own state dir): makes the
/// index when it is missing and `may_create` (no earlier install made
/// it). A later install never makes it again: a missing index then
/// means records were deleted with it, which only `tollgate remotes
/// forget` accepts.
pub fn ensure_index(dirs: &Dirs, may_create: bool) -> Result<IndexSetup, String> {
    ensure_index_in(&records_dir(dirs), may_create)
}

fn ensure_index_in(dir: &Path, may_create: bool) -> Result<IndexSetup, String> {
    let file = index_in(dir);
    let exists = |f: &Path| match std::fs::symlink_metadata(f) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot read the index {}: {e}", f.display())),
    };
    if exists(&file)? {
        return Ok(IndexSetup::Present);
    }
    if !may_create {
        return Ok(IndexSetup::Missing(file));
    }
    let _held = lock(&file)?;
    if exists(&file)? {
        return Ok(IndexSetup::Present);
    }
    let index = rebuild_index(dir)?;
    write_index(&file, &index)?;
    Ok(IndexSetup::Created(index.repos.len()))
}

fn write_index(file: &Path, i: &Index) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(i)
        .map_err(|e| format!("cannot write the index {}: {e}", file.display()))?;
    fsx::write_atomic(file, &json)
        .map_err(|e| format!("cannot write the index {}: {e}", file.display()))
}

fn lock(file: &Path) -> Result<LockFile, String> {
    let path = lock_path(file);
    if let Some(dir) = path.parent() {
        fsx::ensure_dir(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let start = Instant::now();
    let mut pause = Duration::from_millis(1);
    loop {
        match LockFile::try_acquire(&path) {
            Ok(Some(l)) => return Ok(l),
            Ok(None) if start.elapsed() < LOCK_WAIT => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(100));
            }
            Ok(None) => {
                return Err(format!(
                    "{} is held for more than {} s",
                    path.display(),
                    LOCK_WAIT.as_secs()
                ));
            }
            Err(e) => return Err(format!("cannot lock {}: {e}", path.display())),
        }
    }
}

fn has(seen: &[SeenRemote], id: &str) -> bool {
    seen.iter().any(|s| url_identity(&s.url) == id)
}

fn add_commits(to: &mut Vec<Oid>, more: impl IntoIterator<Item = Oid>) {
    for c in more {
        if to.len() >= MAX_COMMITS {
            return;
        }
        if !to.contains(&c) {
            to.push(c);
        }
    }
}

/// One repo as the check sees it.
struct Repo<'a> {
    /// `<state>/trusted-remotes`.
    dir: &'a Path,
    key: &'a RepoKey,
    /// The repo's dir, for the index.
    repo_dir: &'a Path,
    objects: &'a dyn Objects,
}

/// Another indexed repo whose commits this one has.
struct Match {
    key: RepoKey,
    dir: String,
    commits: Vec<Oid>,
    record: Result<Option<Record>, String>,
}

impl Repo<'_> {
    fn file(&self) -> PathBuf {
        record_in(self.dir, self.key)
    }

    fn index_file(&self) -> PathBuf {
        index_in(self.dir)
    }

    /// The indexed repos other than this one (and those in `skip`) whose
    /// commits this repo has.
    fn matches(&self, index: &Index, skip: &[RepoKey]) -> Result<Vec<Match>, String> {
        let others: Vec<(&RepoKey, &IndexEntry)> = index
            .repos
            .iter()
            .filter(|(k, _)| *k != self.key && !skip.contains(k))
            .collect();
        let all: BTreeSet<Oid> = others
            .iter()
            .flat_map(|(_, e)| e.commits.iter().cloned())
            .collect();
        if all.is_empty() {
            return Ok(Vec::new());
        }
        let all: Vec<Oid> = all.into_iter().collect();
        let present = self.objects.present(&all)?;
        Ok(others
            .into_iter()
            .filter_map(|(k, e)| {
                let commits: Vec<Oid> = e
                    .commits
                    .iter()
                    .filter(|c| present.contains(*c))
                    .cloned()
                    .collect();
                (!commits.is_empty()).then(|| Match {
                    key: k.clone(),
                    dir: e.dir.clone(),
                    commits,
                    record: read(&record_in(self.dir, k)),
                })
            })
            .collect())
    }

    /// The record as it should be now, from the record read (`rec`), the
    /// index and the trusted remotes now.
    fn evaluate(
        &self,
        rec: Option<&Record>,
        index: &Index,
        trusted: &[TrustedRemote],
    ) -> Result<Record, String> {
        if rec.is_none() && index.repos.contains_key(self.key) {
            return Err(format!(
                "the record is missing, but the index {} lists this repo",
                self.index_file().display()
            ));
        }
        let mut r = rec.cloned().unwrap_or_default();
        let fresh = r.remotes.is_empty();
        if fresh {
            // A copy, a move or a clone of another repo takes over its
            // recorded remotes.
            for m in self.matches(index, &r.forgot_repos)? {
                let other = match m.record {
                    Ok(Some(o)) => o,
                    Ok(None) => {
                        return Err(format!(
                            "this repo has commits of {}, whose record {} is missing",
                            m.dir,
                            record_in(self.dir, &m.key).display()
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "this repo has commits of {}, whose record {} is unusable: {e}",
                            m.dir,
                            record_in(self.dir, &m.key).display()
                        ));
                    }
                };
                for s in other.remotes {
                    let id = url_identity(&s.url);
                    if has(&r.forgotten, &id) || has(&r.remotes, &id) {
                        continue;
                    }
                    r.remotes.push(SeenRemote {
                        from: s.from.clone().or_else(|| Some(m.dir.clone())),
                        ..s
                    });
                }
                if !r.remotes.is_empty() {
                    add_commits(&mut r.commits, m.commits);
                }
            }
        }
        let now = jiff::Timestamp::now();
        let mut added = false;
        for t in trusted {
            if !has(&r.remotes, &url_identity(&t.url)) {
                r.remotes.push(SeenRemote {
                    name: t.name.clone(),
                    url: t.url.clone(),
                    since: now,
                    from: None,
                });
                added = true;
            }
        }
        // Its own commits too when it starts to hold remotes, so a copy of
        // a copy is told even when the first is gone.
        if !r.remotes.is_empty() && (added || fresh || r.commits.is_empty()) {
            add_commits(&mut r.commits, self.objects.identity(trusted)?);
        }
        Ok(r)
    }

    /// What to write: the record (when it changed and holds something)
    /// and the index (when this repo has remotes and the index does not
    /// list its commits).
    fn writes(&self, rec: Option<&Record>, index: &Index, r: &Record) -> (bool, bool) {
        let record = rec != Some(r) && !(rec.is_none() && *r == Record::default());
        let index = !r.remotes.is_empty()
            && index
                .repos
                .get(self.key)
                .is_none_or(|e| e.commits != r.commits);
        (record, index)
    }

    fn check(&self, trusted: &[TrustedRemote]) -> Status {
        match self.check_inner(trusted) {
            Ok(r) => lost(r.remotes, trusted),
            Err(e) => Status::Broken(e),
        }
    }

    fn check_inner(&self, trusted: &[TrustedRemote]) -> Result<Record, String> {
        let file = self.file();
        let rec = read(&file)?;
        // Hot path (L19): one small file read when the record holds
        // remotes, its commits and every trusted remote.
        if let Some(r) = &rec
            && !r.remotes.is_empty()
            && !r.commits.is_empty()
            && trusted
                .iter()
                .all(|t| has(&r.remotes, &url_identity(&t.url)))
        {
            return Ok(r.clone());
        }
        let index_file = self.index_file();
        // Without the locks first: most repos with no record have nothing
        // to write. An error here may be another writer half done (index
        // written, record not yet), so it is decided under the locks.
        if let Ok(index) = read_index(&index_file)
            && let Ok(r) = self.evaluate(rec.as_ref(), &index, trusted)
            && self.writes(rec.as_ref(), &index, &r) == (false, false)
        {
            return Ok(r);
        }
        // Another hook may be adding too: merge under the locks (record,
        // then index; the only order taken) with what is there now.
        let _held = lock(&file)?;
        let _held_index = lock(&index_file)?;
        let rec = read(&file)?;
        let mut index = read_index(&index_file)?;
        let r = self.evaluate(rec.as_ref(), &index, trusted)?;
        let (w_record, w_index) = self.writes(rec.as_ref(), &index, &r);
        // The index first: a record written without it could be deleted
        // unseen; an index entry without its record denies.
        if w_index {
            index.version = INDEX_VERSION;
            index.repos.insert(
                self.key.clone(),
                IndexEntry {
                    dir: self.repo_dir.display().to_string(),
                    commits: r.commits.clone(),
                },
            );
            write_index(&index_file, &index)?;
        }
        if w_record {
            write(&file, &r)?;
        }
        Ok(r)
    }
}

fn forget_remote(s: SeenRemote, t: &mut Record) {
    if !has(&t.forgotten, &url_identity(&s.url)) {
        t.forgotten.push(s);
    }
}

fn lost(remotes: Vec<SeenRemote>, trusted: &[TrustedRemote]) -> Status {
    let ids: Vec<String> = trusted.iter().map(|t| url_identity(&t.url)).collect();
    let lost: Vec<SeenRemote> = remotes
        .into_iter()
        .filter(|s| !ids.contains(&url_identity(&s.url)))
        .collect();
    if lost.is_empty() {
        Status::Kept
    } else {
        Status::Lost(lost)
    }
}

/// Checks the record of the repo whose key is `repo` (in `repo_dir`,
/// read through `git`) against `trusted` (its trusted remotes now), and
/// adds what is not recorded yet. One small file read when the record
/// holds every trusted remote; the index and a `git cat-file` when the
/// repo has no recorded remote; locks and writes when something is new.
#[must_use]
pub fn check(
    dirs: &Dirs,
    git: &dyn Objects,
    repo: &RepoKey,
    repo_dir: &Path,
    trusted: &[TrustedRemote],
) -> Checked {
    let dir = records_dir(dirs);
    let r = Repo {
        dir: &dir,
        key: repo,
        repo_dir,
        objects: git,
    };
    Checked {
        file: r.file(),
        status: r.check(trusted),
    }
}

/// What `tollgate remotes forget` would accept, for its confirmation.
#[derive(Debug)]
pub struct View {
    /// The record file.
    pub file: PathBuf,
    /// The record, or why it is unusable.
    pub record: Result<Option<Record>, String>,
    /// The index lists the repo.
    pub indexed: bool,
    /// The index is missing (its path): `forget` starts a new one from
    /// this many records left.
    pub index_missing: Option<(PathBuf, usize)>,
    /// Other repos whose commits this one has: dir and their remotes (or
    /// why their record is unusable).
    pub matches: Vec<(String, Result<Vec<SeenRemote>, String>)>,
}

impl View {
    /// Nothing recorded for the repo and nothing to take over.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let own = match &self.record {
            Ok(None) => self.indexed,
            Ok(Some(r)) => !r.remotes.is_empty(),
            Err(_) => true,
        };
        !own && self.index_missing.is_none()
            && self
                .matches
                .iter()
                .all(|(_, m)| m.as_ref().is_ok_and(Vec::is_empty))
    }

    /// The lines the confirmation lists.
    #[must_use]
    pub fn lines(&self) -> String {
        let mut s = String::new();
        if let Some((file, n)) = &self.index_missing {
            s.push_str(&format!(
                "  (the index {} of repos that had trusted remotes is missing, so a repo whose record was deleted with it cannot be told; forget starts a new index from the {n} records left)\n",
                file.display()
            ));
        }
        match &self.record {
            Ok(Some(r)) => {
                for x in &r.remotes {
                    s.push_str(&format!("  {} (since {})\n", x.describe(), x.since));
                }
            }
            Ok(None) if self.indexed => {
                s.push_str("  (the record is missing, but the index lists this repo)\n");
            }
            Ok(None) => {}
            Err(e) => s.push_str(&format!("  (unusable: {e})\n")),
        }
        for (dir, m) in &self.matches {
            match m {
                Ok(remotes) => {
                    for x in remotes {
                        s.push_str(&format!(
                            "  {} ({}, recorded in {dir}, whose commits this repo has)\n",
                            x.name, x.url
                        ));
                    }
                }
                Err(e) => s.push_str(&format!(
                    "  (the record of {dir}, whose commits this repo has, is unusable: {e})\n"
                )),
            }
        }
        s
    }
}

/// The record of `repo` and the repos it would take remotes over from.
#[must_use]
pub fn inspect(dirs: &Dirs, git: &dyn Objects, repo: &RepoKey, repo_dir: &Path) -> View {
    let dir = records_dir(dirs);
    let r = Repo {
        dir: &dir,
        key: repo,
        repo_dir,
        objects: git,
    };
    let file = r.file();
    let record = read(&file);
    let index_file = r.index_file();
    let (index, index_missing) = match load_index(&index_file) {
        Ok(Some(i)) => (Ok(i), None),
        Ok(None) => match rebuild_index(&dir) {
            Ok(i) => {
                let n = i.repos.len();
                (Ok(i), Some((index_file, n)))
            }
            Err(e) => (Err(e), None),
        },
        Err(e) => (Err(e), None),
    };
    let indexed = index.as_ref().is_ok_and(|i| i.repos.contains_key(repo));
    let skip = record
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .map(|x| x.forgot_repos.clone())
        .unwrap_or_default();
    let own_remotes = record
        .as_ref()
        .ok()
        .and_then(Option::as_ref)
        .is_some_and(|x| !x.remotes.is_empty());
    let matches = match index {
        _ if own_remotes => Vec::new(),
        Err(e) => vec![(r.index_file().display().to_string(), Err(e))],
        Ok(i) => match r.matches(&i, &skip) {
            Err(e) => vec![(repo_dir.display().to_string(), Err(e))],
            Ok(ms) => ms
                .into_iter()
                .map(|m| {
                    let remotes = match m.record {
                        Ok(Some(o)) => Ok(o.remotes),
                        Ok(None) => Err("missing".to_owned()),
                        Err(e) => Err(e),
                    };
                    (m.dir, remotes)
                })
                .collect(),
        },
    };
    View {
        file,
        record,
        indexed,
        index_missing,
        matches,
    }
}

/// `tollgate remotes forget`: empties the record of `repo`, a broken or
/// missing one too (a tombstone; the index keeps the repo). The remotes
/// it held and those of the repos whose commits it has now are not taken
/// over again. A missing index is made again from the records left (an
/// unusable one is an error: it is for a person to repair or remove).
pub fn forget(dirs: &Dirs, git: &dyn Objects, repo: &RepoKey, repo_dir: &Path) -> io::Result<()> {
    let dir = records_dir(dirs);
    Repo {
        dir: &dir,
        key: repo,
        repo_dir,
        objects: git,
    }
    .forget()
}

impl Repo<'_> {
    fn forget(&self) -> io::Result<()> {
        let file = self.file();
        let index_file = self.index_file();
        let _held = lock(&file).map_err(io::Error::other)?;
        let _held_index = lock(&index_file).map_err(io::Error::other)?;
        let before = read(&file).ok().flatten().unwrap_or_default();
        let mut index = match load_index(&index_file).map_err(io::Error::other)? {
            Some(i) => i,
            None => rebuild_index(self.dir).map_err(io::Error::other)?,
        };
        let mut tomb = Record {
            remotes: Vec::new(),
            forgotten: before.forgotten,
            forgot_repos: before.forgot_repos,
            commits: before.commits,
        };
        for s in before.remotes {
            forget_remote(s, &mut tomb);
        }
        for m in self
            .matches(&index, &tomb.forgot_repos)
            .map_err(io::Error::other)?
        {
            if let Ok(Some(o)) = m.record {
                for s in o.remotes {
                    forget_remote(s, &mut tomb);
                }
            }
            tomb.forgot_repos.push(m.key);
        }
        index.version = INDEX_VERSION;
        index
            .repos
            .entry(self.key.clone())
            .or_insert_with(|| IndexEntry {
                dir: self.repo_dir.display().to_string(),
                commits: tomb.commits.clone(),
            });
        write_index(&index_file, &index).map_err(io::Error::other)?;
        write(&file, &tomb).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tr(name: &str, url: &str) -> TrustedRemote {
        TrustedRemote {
            name: name.to_owned(),
            url: url.to_owned(),
        }
    }

    fn lost_names(s: &Status) -> Vec<String> {
        match s {
            Status::Lost(l) => l.iter().map(|r| r.name.clone()).collect(),
            other => panic!("not lost: {other:?}"),
        }
    }

    fn oid(n: u8) -> Oid {
        Oid::parse(&format!("{n:02x}").repeat(20)).unwrap()
    }

    /// An object store with these commits; `identity` is `HEAD` (the
    /// first), as a repo with no tracking refs has.
    struct Store(Vec<Oid>);

    impl Objects for Store {
        fn present(&self, commits: &[Oid]) -> Result<BTreeSet<Oid>, String> {
            Ok(commits
                .iter()
                .filter(|c| self.0.contains(c))
                .cloned()
                .collect())
        }
        fn identity(&self, _: &[TrustedRemote]) -> Result<Vec<Oid>, String> {
            Ok(self.0.first().cloned().into_iter().collect())
        }
    }

    /// A store that must not be asked (the hot path).
    struct Unasked;

    impl Objects for Unasked {
        fn present(&self, _: &[Oid]) -> Result<BTreeSet<Oid>, String> {
            panic!("asked the object store")
        }
        fn identity(&self, _: &[TrustedRemote]) -> Result<Vec<Oid>, String> {
            panic!("asked the object store")
        }
    }

    /// A records dir in `tmp` with the index install makes.
    fn records(tmp: &Path) -> PathBuf {
        let d = tmp.join("trusted-remotes");
        assert_eq!(ensure_index_in(&d, true), Ok(IndexSetup::Created(0)));
        d
    }

    fn key(n: u8) -> RepoKey {
        RepoKey::parse(&format!("{n:016x}")).unwrap()
    }

    /// `check` of repo `k` in the records dir `dir`.
    fn at(dir: &Path, k: u8, objects: &dyn Objects, trusted: &[TrustedRemote]) -> Status {
        let key = key(k);
        let repo_dir = PathBuf::from(format!("/r/{k}"));
        Repo {
            dir,
            key: &key,
            repo_dir: &repo_dir,
            objects,
        }
        .check(trusted)
    }

    fn forget_at(dir: &Path, k: u8, objects: &dyn Objects) {
        let key = key(k);
        let repo_dir = PathBuf::from(format!("/r/{k}"));
        Repo {
            dir,
            key: &key,
            repo_dir: &repo_dir,
            objects,
        }
        .forget()
        .unwrap();
    }

    /// Item 33, secreview note 2, with real git: `present` names only the
    /// ids that are commits in the repo (not a tree, not a missing id);
    /// `identity` is the root commits of `HEAD` and of the trusted
    /// remote's tracking refs, as written (a replace ref that makes a
    /// commit parentless does not change them).
    #[test]
    fn git_finds_root_commits_and_present_ones_note2() {
        let tmp = tempfile::tempdir().unwrap();
        let env = crate::env::EnvSnapshot::capture();
        let run = |dir: &Path, args: &[&str]| -> String {
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .env_clear()
                .env("PATH", std::env::var_os("PATH").unwrap_or_default())
                .env("HOME", tmp.path())
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .output()
                .unwrap();
            assert!(out.status.success(), "{args:?}: {out:?}");
            String::from_utf8(out.stdout).unwrap().trim().to_owned()
        };
        let up = tmp.path().join("up");
        let repo = tmp.path().join("repo");
        std::fs::create_dir_all(&up).unwrap();
        run(&up, &["init", "-q"]);
        run(&up, &["commit", "-q", "--allow-empty", "-m", "up root"]);
        let up_root = run(&up, &["rev-parse", "HEAD"]);
        run(&up, &["commit", "-q", "--allow-empty", "-m", "up 2"]);
        std::fs::create_dir_all(&repo).unwrap();
        run(&repo, &["init", "-q"]);
        let git = Git::scrubbed(&env, &repo);
        assert_eq!(git.identity(&[]).unwrap(), Vec::<Oid>::new(), "unborn");
        run(&repo, &["commit", "-q", "--allow-empty", "-m", "own root"]);
        let own_root = run(&repo, &["rev-parse", "HEAD"]);
        run(&repo, &["commit", "-q", "--allow-empty", "-m", "own 2"]);
        let own_2 = run(&repo, &["rev-parse", "HEAD"]);
        run(&repo, &["remote", "add", "origin", up.to_str().unwrap()]);
        run(&repo, &["fetch", "-q", "origin"]);
        let o = |x: &str| Oid::parse(x).unwrap();
        let mut both = vec![o(&own_root), o(&up_root)];
        both.sort();
        assert_eq!(git.identity(&[tr("origin", "/up")]).unwrap(), both);
        assert_eq!(git.identity(&[]).unwrap(), [o(&own_root)]);
        let fake = run(
            &repo,
            &["commit-tree", "-m", "fake", &format!("{own_2}^{{tree}}")],
        );
        run(&repo, &["replace", &own_2, &fake]);
        assert_eq!(git.identity(&[]).unwrap(), [o(&own_root)]);
        // Present: commits only, in any order, with missing ids around.
        let tree = o(&run(&repo, &["rev-parse", "HEAD^{tree}"]));
        let missing = o(&"ab".repeat(20));
        let asked = [missing.clone(), o(&up_root), tree, o(&own_2), missing];
        let got = git.present(&asked).unwrap();
        assert_eq!(got, BTreeSet::from([o(&up_root), o(&own_2)]));
    }

    /// Item 33: the record keeps every trusted remote once seen; a remote
    /// whose URL identity no trusted remote has now is lost. A rename or
    /// another spelling of the same URL is not a loss; another URL is.
    #[test]
    fn a_recorded_remote_is_lost_only_when_its_url_is_gone_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        let s = Store(vec![oid(1)]);
        let gl = "https://gitlab.com/victorkwak/r.git";
        assert_eq!(at(&d, 1, &s, &[]), Status::Kept);
        assert!(
            !record_in(&d, &key(1)).exists(),
            "nothing to record: no file"
        );
        assert_eq!(at(&d, 1, &s, &[tr("origin", gl)]), Status::Kept);
        // Renamed, and spelled another way: kept.
        assert_eq!(
            at(
                &d,
                1,
                &s,
                &[tr("upstream", "https://GitLab.com/victorkwak/r")]
            ),
            Status::Kept
        );
        // Gone, or only another trusted remote left: lost.
        assert_eq!(lost_names(&at(&d, 1, &s, &[])), ["origin"]);
        let other = tr("mirror", "git@gitlab.com:victorkwak/other.git");
        assert_eq!(
            lost_names(&at(&d, 1, &s, std::slice::from_ref(&other))),
            ["origin"]
        );
        // The other one is recorded too, and both back is kept.
        assert_eq!(
            at(&d, 1, &s, &[tr("origin", gl), other.clone()]),
            Status::Kept
        );
        assert_eq!(lost_names(&at(&d, 1, &s, &[tr("o", gl)])), ["mirror"]);
        // The record stores URLs as git used them, once per identity, and
        // the repo's commits; the index lists the repo with them.
        let r = read(&record_in(&d, &key(1))).unwrap().unwrap();
        assert_eq!(
            r.remotes.iter().map(|s| s.url.as_str()).collect::<Vec<_>>(),
            [gl, other.url.as_str()]
        );
        assert_eq!(r.commits, [oid(1)]);
        let i = read_index(&index_in(&d)).unwrap();
        assert_eq!(i.repos[&key(1)].commits, [oid(1)]);
        // With everything recorded, the object store is not asked.
        assert_eq!(
            at(&d, 1, &Unasked, &[tr("origin", gl), other]),
            Status::Kept
        );
    }

    /// Item 33, secreview note 2: a copy or a move of a repo (another key,
    /// the same commits) takes over its recorded remotes, so removing the
    /// remote before the first check in the new path is a loss; one that
    /// keeps it is kept. A repo with none of its commits is not.
    #[test]
    fn a_copy_takes_over_the_recorded_remotes_note2() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        let gl = [tr("origin", "https://gitlab.com/victorkwak/r.git")];
        let s = Store(vec![oid(1), oid(2)]);
        assert_eq!(at(&d, 1, &s, &gl), Status::Kept);
        // Moved or copied, origin removed: lost, named with where it was
        // recorded.
        let moved = Store(vec![oid(3), oid(1)]);
        let st = at(&d, 2, &moved, &[]);
        assert_eq!(lost_names(&st), ["origin"]);
        let Status::Lost(l) = &st else { unreachable!() };
        assert_eq!(l[0].from.as_deref(), Some("/r/1"));
        // It stays lost with the record now held under the new key.
        assert_eq!(lost_names(&at(&d, 2, &Unasked, &[])), ["origin"]);
        // A copy that keeps origin: kept.
        assert_eq!(at(&d, 3, &Store(vec![oid(1)]), &gl), Status::Kept);
        // Another URL in its place: lost.
        let evil = [tr("origin", "https://gitlab.com/victorkwak/evil.git")];
        assert_eq!(
            lost_names(&at(&d, 4, &Store(vec![oid(1)]), &evil)),
            ["origin"]
        );
        // A repo with none of its commits: nothing to take over, nothing
        // written.
        assert_eq!(at(&d, 5, &Store(vec![oid(9)]), &[]), Status::Kept);
        assert!(!record_in(&d, &key(5)).exists());
        // A copy of the copy: the first recorded place is named.
        let st = at(&d, 6, &Store(vec![oid(3)]), &[]);
        let Status::Lost(l) = &st else {
            panic!("{st:?}")
        };
        assert_eq!(l[0].from.as_deref(), Some("/r/1"));
    }

    /// Item 33, secreview note 3: a deleted record of a repo the index
    /// lists is unusable, never "no record"; so is a deleted record of a
    /// repo whose commits this one has, and an unusable index.
    #[test]
    fn a_missing_record_of_a_known_repo_denies_note3() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        let gl = [tr("origin", "https://gitlab.com/victorkwak/r.git")];
        let s = Store(vec![oid(1)]);
        let broken = |st: Status, what: &str| {
            assert!(
                matches!(&st, Status::Broken(w) if w.contains(what)),
                "{st:?}"
            );
        };
        assert_eq!(at(&d, 1, &s, &gl), Status::Kept);
        std::fs::remove_file(record_in(&d, &key(1))).unwrap();
        broken(at(&d, 1, &s, &[]), "index");
        broken(at(&d, 1, &s, &gl), "index");
        // Its copy: the record it would take over is missing.
        broken(at(&d, 2, &Store(vec![oid(1)]), &[]), "missing");
        // An unusable index, for a repo with no record.
        std::fs::write(index_in(&d), "{not json").unwrap();
        broken(at(&d, 3, &Store(vec![oid(7)]), &[]), "index");
    }

    /// Item 33, secreview note 27: a missing index never reads as "no
    /// repo had trusted remotes". Deleted with a record (or with every
    /// record), it denies every repo that needs it; install makes it only
    /// once; `forget` makes it again from the records left, so a repo
    /// whose record survived still tells its copies.
    #[test]
    fn a_missing_index_denies_until_forget_makes_it_again_note27() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        let gl = [tr("origin", "https://gitlab.com/victorkwak/r.git")];
        let other = [tr("o2", "https://gitlab.com/victorkwak/other.git")];
        let missing = |st: Status| {
            assert!(
                matches!(&st, Status::Broken(w) if w.contains("is missing") && w.contains(INDEX_MISSING_FIX)),
                "{st:?}"
            );
            let c = Checked {
                file: PathBuf::new(),
                status: st,
            };
            assert!(c.deny_message().unwrap().contains("remotes forget"));
        };
        let (s1, s5) = (Store(vec![oid(1)]), Store(vec![oid(5)]));
        assert_eq!(at(&d, 1, &s1, &gl), Status::Kept);
        assert_eq!(at(&d, 5, &s5, &other), Status::Kept);
        // An install with a present index (usable or not) leaves it.
        assert_eq!(ensure_index_in(&d, true), Ok(IndexSetup::Present));
        std::fs::remove_file(index_in(&d)).unwrap();
        std::fs::remove_file(record_in(&d, &key(1))).unwrap();
        // Repo 1 lost its record and origin: denied, not "new".
        missing(at(&d, 1, &s1, &[]));
        // A repo with no record and no remote, a copy of 5: denied too.
        missing(at(&d, 6, &Store(vec![oid(5), oid(6)]), &[]));
        // A repo whose own record holds its trusted remote reads no index.
        assert_eq!(at(&d, 5, &Unasked, &other), Status::Kept);
        // Nothing was written meanwhile.
        assert!(!index_in(&d).exists());
        // A later install does not make it again.
        assert_eq!(
            ensure_index_in(&d, false),
            Ok(IndexSetup::Missing(index_in(&d)))
        );
        missing(at(&d, 1, &s1, &[]));
        // A dangling symlink in its place is missing too, and install
        // does not write through it.
        let target = tmp.path().join("elsewhere.json");
        std::os::unix::fs::symlink(&target, index_in(&d)).unwrap();
        missing(at(&d, 1, &s1, &[]));
        assert_eq!(ensure_index_in(&d, true), Ok(IndexSetup::Present));
        assert!(!target.exists());
        std::fs::remove_file(index_in(&d)).unwrap();
        // A dir in its place is unusable.
        std::fs::create_dir(index_in(&d)).unwrap();
        assert!(matches!(at(&d, 1, &s1, &[]), Status::Broken(_)));
        std::fs::remove_dir(index_in(&d)).unwrap();
        // `forget` in repo 1 accepts the loss: a new index from the
        // records left, so repo 5 still tells its copies.
        forget_at(&d, 1, &s1);
        assert_eq!(at(&d, 1, &s1, &[]), Status::Kept);
        assert_eq!(
            lost_names(&at(&d, 6, &Store(vec![oid(5), oid(6)]), &[])),
            ["o2"]
        );
        // An unusable record left is listed with no commits, so its repo
        // still denies after the index is made again.
        std::fs::remove_file(index_in(&d)).unwrap();
        std::fs::write(record_in(&d, &key(7)), "{not json").unwrap();
        assert_eq!(ensure_index_in(&d, true), Ok(IndexSetup::Created(4)));
        assert!(matches!(
            at(&d, 7, &Store(vec![oid(7)]), &[]),
            Status::Broken(_)
        ));
    }

    /// Item 33, secreview note 3: `forget` leaves a tombstone. The repo
    /// is not taken as unknown, the remotes it accepted are not taken over
    /// again from the repo it is a copy of, and a new trusted remote is
    /// recorded as usual. A different repo moved into a forgotten path
    /// still takes over its own remotes.
    #[test]
    fn forget_leaves_a_tombstone_note3() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        let gl = [tr("origin", "https://gitlab.com/victorkwak/r.git")];
        let s = Store(vec![oid(1)]);
        assert_eq!(at(&d, 1, &s, &gl), Status::Kept);
        // A copy with origin removed is lost; forgetting accepts it.
        let copy = Store(vec![oid(1), oid(2)]);
        assert_eq!(lost_names(&at(&d, 2, &copy, &[])), ["origin"]);
        forget_at(&d, 2, &copy);
        assert!(record_in(&d, &key(2)).exists(), "a tombstone, not removed");
        assert_eq!(at(&d, 2, &copy, &[]), Status::Kept);
        // A copy never checked before its forget: accepted the same way.
        let fresh = Store(vec![oid(1), oid(4)]);
        forget_at(&d, 4, &fresh);
        assert_eq!(at(&d, 4, &fresh, &[]), Status::Kept);
        // Forgetting the original itself, after its record was deleted.
        std::fs::remove_file(record_in(&d, &key(1))).unwrap();
        assert!(matches!(at(&d, 1, &s, &[]), Status::Broken(_)));
        forget_at(&d, 1, &s);
        assert_eq!(at(&d, 1, &s, &[]), Status::Kept);
        // A new trusted remote in the forgotten repo is recorded again.
        assert_eq!(at(&d, 2, &copy, &gl), Status::Kept);
        assert_eq!(lost_names(&at(&d, 2, &copy, &[])), ["origin"]);
        // Another repo (with its own record) moved into a forgotten path
        // takes over its own remotes.
        let other = [tr("o2", "https://gitlab.com/victorkwak/other.git")];
        assert_eq!(at(&d, 5, &Store(vec![oid(5)]), &other), Status::Kept);
        assert_eq!(lost_names(&at(&d, 4, &Store(vec![oid(5)]), &[])), ["o2"]);
    }

    /// Item 33, fail closed: a record that cannot be parsed or read, has
    /// another version, or cannot be written denies; it is never taken as
    /// "no record".
    #[test]
    fn an_unusable_record_denies_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = records(tmp.path());
        let gl = [tr("origin", "https://gitlab.com/victorkwak/r.git")];
        let s = Store(vec![oid(1)]);
        let broken = |st: Status| matches!(st, Status::Broken(_));
        let f = record_in(&dir, &key(1));
        for text in [
            "{not json",
            "",
            "[]",
            r#"{"version":3,"remotes":[]}"#,
            r#"{"version":1,"remotes":[],"x":1}"#,
            r#"{"version":2,"remotes":[],"commits":["zz"]}"#,
        ] {
            std::fs::write(&f, text).unwrap();
            assert!(broken(at(&dir, 1, &s, &[])), "{text:?}");
            assert!(broken(at(&dir, 1, &s, &gl)), "{text:?}");
        }
        // A version 1 record reads, and gets its commits.
        std::fs::write(
            &f,
            r#"{"version":1,"remotes":[{"name":"origin","url":"https://gitlab.com/victorkwak/r.git","since":"2026-11-05T00:00:00Z"}]}"#,
        )
        .unwrap();
        assert_eq!(at(&dir, 1, &s, &gl), Status::Kept);
        assert_eq!(read(&f).unwrap().unwrap().commits, [oid(1)]);
        // A dir where the file should be: unreadable.
        std::fs::create_dir(record_in(&dir, &key(2))).unwrap();
        assert!(broken(at(&dir, 2, &s, &gl)));
        // Cannot be written: the records dir is a file.
        let blocked = tmp.path().join("file");
        std::fs::write(&blocked, "x").unwrap();
        assert!(broken(at(&blocked, 3, &s, &gl)));
        // Not even readable (not a dir): denies with nothing to record too.
        assert!(broken(at(&blocked, 3, &s, &[])));
    }

    /// Item 33: a writer that holds the record's lock longer than
    /// [`LOCK_WAIT`] makes the check deny, not hang.
    #[test]
    fn a_held_record_lock_denies_after_a_bounded_wait_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        std::fs::create_dir_all(&d).unwrap();
        let s = Store(vec![oid(1)]);
        let held = LockFile::acquire(&lock_path(&record_in(&d, &key(1)))).unwrap();
        let start = Instant::now();
        let st = at(&d, 1, &s, &[tr("origin", "/srv/r.git")]);
        assert!(
            matches!(st, Status::Broken(ref w) if w.contains("held")),
            "{st:?}"
        );
        assert!(start.elapsed() < LOCK_WAIT + Duration::from_secs(1));
        drop(held);
        assert_eq!(at(&d, 1, &s, &[tr("origin", "/srv/r.git")]), Status::Kept);
    }

    /// Item 33: concurrent writers that add different remotes keep both,
    /// and concurrent repos all reach the index.
    #[test]
    fn concurrent_writers_keep_every_remote_item33() {
        let tmp = tempfile::tempdir().unwrap();
        let d = records(tmp.path());
        // A holder slower than LOCK_WAIT, as on a loaded host (in a gate
        // job at load 40, 16 writers with four fsyncs each outran 2 s). A
        // writer that waits too long denies (fail closed); its user runs
        // the command again, so each writer here retries that deny only,
        // and no write is lost.
        let held = LockFile::acquire(&lock_path(&index_in(&d))).unwrap();
        let write = |k: u8, r: TrustedRemote| {
            for _ in 0..20 {
                match at(&d, k, &Store(vec![oid(k)]), std::slice::from_ref(&r)) {
                    Status::Broken(w) if w.contains("is held for more than") => {}
                    Status::Broken(w) => panic!("writer {k}: {w}"),
                    _ => return,
                }
            }
            panic!("writer {k}: the lock stayed held");
        };
        std::thread::scope(|s| {
            s.spawn(move || {
                std::thread::sleep(LOCK_WAIT + Duration::from_millis(300));
                drop(held);
            });
            for i in 0..8u8 {
                let write = &write;
                s.spawn(move || write(1, tr(&format!("r{i}"), &format!("/srv/r{i}.git"))));
                s.spawn(move || write(10 + i, tr("origin", &format!("/srv/k{i}.git"))));
            }
        });
        let mut names: Vec<String> = read(&record_in(&d, &key(1)))
            .unwrap()
            .unwrap()
            .remotes
            .into_iter()
            .map(|r| r.name)
            .collect();
        names.sort();
        assert_eq!(names, (0..8).map(|i| format!("r{i}")).collect::<Vec<_>>());
        let i = read_index(&index_in(&d)).unwrap();
        assert_eq!(i.repos.len(), 9);
    }
}
