//! Push candidates: one commit in the gate per full-tier ref (R111, R112).
//!
//! A push candidate is a commit that a `pre-push` hook checks at tier
//! `full` for a branch of a trusted remote, in a push that is not forced.
//! `<state>/push-candidates/<blake3 of (URL identity, remote ref)[..32]>.json`
//! lists the candidates of one ref on this machine. The URL identity is the
//! one of the trusted-remote records ([`url_identity`]), so two clones and
//! all worktrees of one repo share the file. Every read-modify-write holds
//! an exclusive `flock` on the sibling `.lock` file ([`Lane::open`]); the
//! file itself is replaced by an atomic rename, so a crash leaves the old
//! or the new list, never half of one.
//!
//! An entry is live while its job is queued or running; while its job
//! passed and less than `candidate_hold` went by since the pass, or since
//! the hook allowed its push; it is not live when its job ended in any
//! other way, when the job dir is gone, or when the remote's value (from
//! the push's stdin) contains its commit (it landed). [`Lane::prune`]
//! removes the entries that are not live; every reader calls it.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::cache::record::Verdict;
use crate::config::trust::url_identity;
use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::Oid;
use crate::ids::JobId;
use crate::locks::LockFile;
use crate::sched::{self, JobState, JobStore};

const VERSION: u32 = 1;

/// One candidate commit of a ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// The pushed commit.
    pub commit: Oid,
    /// Its tree.
    pub tree: Oid,
    /// The job that checks it (created or attached to).
    pub job: JobId,
    /// The worktree the push came from.
    pub worktree: PathBuf,
    /// The local ref that was pushed.
    pub local_ref: String,
    /// The remote's name in that repo.
    pub remote: String,
    /// The trusted fetch URL of that remote, as git uses it: the URL the
    /// remote check of R112 asks.
    pub url: String,
    /// When the hook added the entry.
    pub time: jiff::Timestamp,
    /// When its job passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passed: Option<jiff::Timestamp>,
    /// When a hook last allowed its push (a stored pass).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed: Option<jiff::Timestamp>,
}

/// The file of one ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneFile {
    version: u32,
    /// URL identity of the remote ([`url_identity`]).
    pub identity: String,
    /// The remote ref (`refs/heads/main`).
    pub remote_ref: String,
    /// Candidates, oldest first.
    #[serde(default)]
    pub entries: Vec<Candidate>,
}

/// Why an entry is live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Live {
    /// Its job waits, since then.
    Queued(jiff::Timestamp),
    /// Its job runs, since then.
    Running(jiff::Timestamp),
    /// Its job passed then; the ref is held for `candidate_hold` after
    /// the pass or the last allowed push.
    Passed(jiff::Timestamp),
}

impl Live {
    /// `queued`, `running` or `passed`.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Queued(_) => "queued",
            Self::Running(_) => "running",
            Self::Passed(_) => "passed",
        }
    }

    /// Since when it is in that state.
    #[must_use]
    pub fn since(&self) -> jiff::Timestamp {
        match self {
            Self::Queued(t) | Self::Running(t) | Self::Passed(t) => *t,
        }
    }
}

/// The file name stem of a ref's lane: 32 hex digits of blake3 over the
/// URL identity and the remote ref.
#[must_use]
pub fn lane_stem(identity: &str, remote_ref: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"tollgate push lane\0");
    h.update(identity.as_bytes());
    h.update(b"\0");
    h.update(remote_ref.as_bytes());
    h.finalize().to_hex()[..32].to_owned()
}

/// The identity of the trusted fetch URL `url` (as the trusted-remote
/// records compare URLs).
#[must_use]
pub fn identity_of(url: &str) -> String {
    url_identity(url)
}

/// The mtime of `path` as a timestamp.
fn mtime(path: &Path) -> Option<jiff::Timestamp> {
    let t = std::fs::metadata(path).ok()?.modified().ok()?;
    jiff::Timestamp::try_from(t).ok()
}

/// Whether `c` is live now (without the landed test, which needs the
/// remote's value). A passed job gets its pass time recorded in `c` (the
/// mtime of `job.json`, written when the job ended).
pub fn liveness(
    dirs: &Dirs,
    c: &mut Candidate,
    hold: Duration,
    now: jiff::Timestamp,
) -> Option<Live> {
    let meta = JobStore::new(dirs).read(&c.job).ok()?;
    match meta.state {
        // A job whose runner died holds no ref; it is reaped here.
        JobState::Queued | JobState::Running { .. } if !sched::runner_alive(dirs, &meta) => None,
        JobState::Queued => Some(Live::Queued(meta.created)),
        JobState::Running { started, .. } => Some(Live::Running(started)),
        JobState::Finished {
            verdict: Verdict::Pass,
        } => {
            // A time in the future (a clock that was ahead) is kept as
            // now, so it holds the ref for at most `hold`.
            let passed = c
                .passed
                .unwrap_or_else(|| mtime(&dirs.job_dir(&c.job).join("job.json")).unwrap_or(now))
                .min(now);
            c.passed = Some(passed);
            if let Some(a) = c.allowed {
                c.allowed = Some(a.min(now));
            }
            let last = c.allowed.map_or(passed, |a| a.max(passed));
            let held = now.duration_since(last).unsigned_abs() < hold;
            held.then_some(Live::Passed(passed))
        }
        _ => None,
    }
}

/// A short age: `45s`, `3m12s`, `2h05m`.
#[must_use]
pub fn age_text(d: Duration) -> String {
    let s = d.as_secs();
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

/// One ref's candidates, read and locked.
#[derive(Debug)]
pub struct Lane {
    lock: LockFile,
    path: PathBuf,
    /// The list.
    pub file: LaneFile,
}

impl Lane {
    /// Locks and reads the lane of (`identity`, `remote_ref`). A missing
    /// or unreadable file is an empty list.
    pub fn open(dirs: &Dirs, identity: &str, remote_ref: &str) -> io::Result<Self> {
        let stem = lane_stem(identity, remote_ref);
        let dir = dirs.push_candidates_dir();
        Self::open_path(&dir.join(format!("{stem}.json")), identity, remote_ref)
    }

    fn open_path(path: &Path, identity: &str, remote_ref: &str) -> io::Result<Self> {
        let lock = LockFile::acquire(&path.with_extension("lock"))?;
        let file = fsx::read_optional(path)?
            .and_then(|b| serde_json::from_slice::<LaneFile>(&b).ok())
            .filter(|f| f.version == VERSION)
            .unwrap_or_else(|| LaneFile {
                version: VERSION,
                identity: identity.to_owned(),
                remote_ref: remote_ref.to_owned(),
                entries: Vec::new(),
            });
        Ok(Self {
            lock,
            path: path.to_owned(),
            file,
        })
    }

    /// Locks and reads the lane file at `path` (a `.json` file of the
    /// dir), with the identity and ref it names.
    fn open_existing(path: &Path) -> Option<Self> {
        let bytes = fsx::read_optional(path).ok()??;
        let f: LaneFile = serde_json::from_slice(&bytes).ok()?;
        Self::open_path(path, &f.identity, &f.remote_ref).ok()
    }

    /// Removes the entries that are not live; `landed` tells a commit the
    /// remote's current value contains. Returns the live entries with
    /// their state, oldest first.
    pub fn prune(
        &mut self,
        dirs: &Dirs,
        hold: Duration,
        now: jiff::Timestamp,
        landed: &dyn Fn(&Oid) -> bool,
    ) -> Vec<(Candidate, Live)> {
        let mut live = Vec::new();
        self.file.entries.retain_mut(|c| {
            if landed(&c.commit) {
                return false;
            }
            match liveness(dirs, c, hold, now) {
                Some(l) => {
                    live.push((c.clone(), l));
                    true
                }
                None => false,
            }
        });
        live.sort_by_key(|(c, _)| c.time);
        live
    }

    /// Adds `c`, or replaces the entry of the same commit (a repeated
    /// push keeps its first time).
    pub fn upsert(&mut self, mut c: Candidate) {
        if let Some(old) = self.file.entries.iter_mut().find(|e| e.commit == c.commit) {
            c.time = old.time;
            if old.job == c.job {
                c.passed = c.passed.or(old.passed);
                c.allowed = c.allowed.or(old.allowed);
            }
            *old = c;
        } else {
            self.file.entries.push(c);
        }
    }

    /// R111: a hook allowed the push of `commit` from a stored pass.
    /// Returns true when the lane has an entry for it.
    pub fn mark_allowed(&mut self, commit: &Oid, now: jiff::Timestamp) -> bool {
        let mut found = false;
        for e in self.file.entries.iter_mut().filter(|e| e.commit == *commit) {
            e.allowed = Some(now);
            found = true;
        }
        found
    }

    /// Removes the entries of job `job`.
    pub fn remove_job(&mut self, job: &JobId) {
        self.file.entries.retain(|e| e.job != *job);
    }

    /// Writes the list by atomic rename; the lock is still held.
    pub fn save(&self) -> io::Result<()> {
        let json = serde_json::to_vec_pretty(&self.file).map_err(io::Error::other)?;
        fsx::write_atomic(&self.path, &json)
    }

    /// Removes the file and its lock file while the lock is held (gc).
    fn remove(self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        self.lock.remove_locked()
    }
}

/// The lane files of the state dir.
fn lane_files(dirs: &Dirs) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dirs.push_candidates_dir())
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension().is_some_and(|x| x == "json")
                        && !p
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy().starts_with('.'))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

/// The candidates whose job is `job`, with the ref they are for: what the
/// remote check of `job` asks about (R112). Read without the lock: each
/// file is replaced whole.
#[must_use]
pub fn of_job(dirs: &Dirs, job: &JobId) -> Vec<(String, Candidate)> {
    let mut out = Vec::new();
    for p in lane_files(dirs) {
        let Some(f) = fsx::read_optional(&p)
            .ok()
            .flatten()
            .and_then(|b| serde_json::from_slice::<LaneFile>(&b).ok())
        else {
            continue;
        };
        for c in f.entries.into_iter().filter(|c| c.job == *job) {
            out.push((f.remote_ref.clone(), c));
        }
    }
    out
}

/// Removes every entry of `job` (R112: the job is ended).
pub fn remove_job(dirs: &Dirs, job: &JobId) {
    for p in lane_files(dirs) {
        let Some(mut lane) = Lane::open_existing(&p) else {
            continue;
        };
        if lane.file.entries.iter().any(|e| e.job == *job) {
            lane.remove_job(job);
            let _ = lane.save();
        }
    }
}

/// A live candidate with its ref, for `tollgate status`.
#[derive(Debug, Clone)]
pub struct Listed {
    /// URL identity.
    pub identity: String,
    /// Remote ref.
    pub remote_ref: String,
    /// The entry.
    pub candidate: Candidate,
    /// Its state.
    pub live: Live,
}

/// The live candidates of the refs of `identities` (every identity when
/// empty); entries that are not live are removed on the way.
#[must_use]
pub fn live_candidates(dirs: &Dirs, identities: &[String], hold: Duration) -> Vec<Listed> {
    let now = jiff::Timestamp::now();
    let mut out = Vec::new();
    for p in lane_files(dirs) {
        let Some(mut lane) = Lane::open_existing(&p) else {
            continue;
        };
        if !identities.is_empty() && !identities.contains(&lane.file.identity) {
            continue;
        }
        let before = lane.file.entries.len();
        let live = lane.prune(dirs, hold, now, &|_| false);
        if lane.file.entries.len() != before {
            let _ = lane.save();
        }
        for (c, l) in live {
            out.push(Listed {
                identity: lane.file.identity.clone(),
                remote_ref: lane.file.remote_ref.clone(),
                candidate: c,
                live: l,
            });
        }
    }
    out
}

/// gc: removes the lane files with no live entry; returns how many.
#[must_use]
pub fn gc(dirs: &Dirs, hold: Duration) -> usize {
    let now = jiff::Timestamp::now();
    let mut removed = 0;
    for p in lane_files(dirs) {
        let Some(mut lane) = Lane::open_existing(&p) else {
            // Unreadable: nothing in it can be live.
            if let Ok(Some(lock)) = LockFile::try_acquire(&p.with_extension("lock")) {
                let _ = std::fs::remove_file(&p);
                let _ = lock.remove_locked();
                removed += 1;
            }
            continue;
        };
        if lane.prune(dirs, hold, now, &|_| false).is_empty() {
            if lane.remove().is_ok() {
                removed += 1;
            }
        } else {
            let _ = lane.save();
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Tier;
    use crate::ids::RecordKey;
    use crate::locks::Priority;
    use crate::sched::{JobMeta, Origin, StateKind};

    fn dirs(root: &Path) -> Dirs {
        let env = crate::env::EnvSnapshot::from_pairs([
            ("HOME", root.join("home").into_os_string()),
            ("XDG_STATE_HOME", root.join("state").into_os_string()),
            ("XDG_DATA_HOME", root.join("data").into_os_string()),
            ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
        ]);
        Dirs::from_env(&env).unwrap()
    }

    fn oid(c: char) -> Oid {
        Oid::parse(&c.to_string().repeat(40)).unwrap()
    }

    fn job(dirs: &Dirs, n: u8, state: JobState) -> JobId {
        let now = jiff::Timestamp::now();
        let id = JobId::generate(now);
        let meta = JobMeta {
            id: id.clone(),
            key: RecordKey::from_hash(&blake3::hash(&[n])),
            tree: oid('9'),
            tier: Tier::Full,
            origin: Origin {
                worktree: PathBuf::from("/w"),
                refname: "refs/heads/main".into(),
            },
            priority: Priority::Hook,
            created: now,
            state: JobState::Queued,
        };
        let store = JobStore::new(dirs);
        // A live job's runner holds its key lock (R88): kept for the test.
        if !state.is_terminal()
            && let crate::sched::Claim::Owner(claim) =
                crate::sched::claim_job(dirs, &meta.key, &id).unwrap()
        {
            std::mem::forget(claim);
        }
        store.create(&meta).unwrap();
        if state != JobState::Queued {
            store.transition(&id, &[StateKind::Queued], state).unwrap();
        }
        id
    }

    fn cand(commit: char, job: &JobId) -> Candidate {
        Candidate {
            commit: oid(commit),
            tree: oid('9'),
            job: job.clone(),
            worktree: PathBuf::from("/w"),
            local_ref: "refs/heads/x".into(),
            remote: "origin".into(),
            url: "/srv/r.git".into(),
            time: jiff::Timestamp::now(),
            passed: None,
            allowed: None,
        }
    }

    /// R111: the liveness rules, one lock per ref file, a file per
    /// (identity, ref), and entries that are not live removed at a read.
    #[test]
    fn candidates_are_live_by_their_job_and_the_hold_r111() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        let hold = Duration::from_secs(600);
        let now = jiff::Timestamp::now();
        let queued = job(&d, 1, JobState::Queued);
        let running = job(
            &d,
            2,
            JobState::Running {
                started: now,
                pid: 1,
            },
        );
        let passed = job(
            &d,
            3,
            JobState::Finished {
                verdict: Verdict::Pass,
            },
        );
        let failed = job(
            &d,
            4,
            JobState::Finished {
                verdict: Verdict::Fail,
            },
        );
        let cancelled = job(&d, 5, JobState::Cancelled { reason: None });
        let id = identity_of("/srv/r.git");
        {
            let mut lane = Lane::open(&d, &id, "refs/heads/main").unwrap();
            for (c, j) in [
                ('a', &queued),
                ('b', &running),
                ('c', &passed),
                ('d', &failed),
                ('e', &cancelled),
            ] {
                lane.upsert(cand(c, j));
            }
            // A job dir that is gone.
            let gone = JobId::generate(now);
            lane.upsert(cand('f', &gone));
            lane.save().unwrap();
        }
        // Another ref of the same remote is another file.
        assert_ne!(
            lane_stem(&id, "refs/heads/main"),
            lane_stem(&id, "refs/heads/other")
        );
        assert!(
            Lane::open(&d, &id, "refs/heads/other")
                .unwrap()
                .file
                .entries
                .is_empty()
        );
        // Two spellings of one URL are one identity.
        assert_eq!(identity_of("/srv/./r.git"), id);
        let mut lane = Lane::open(&d, &id, "refs/heads/main").unwrap();
        let live = lane.prune(&d, hold, now, &|c| *c == oid('b'));
        let names: Vec<(char, &str)> = live
            .iter()
            .map(|(c, l)| (c.commit.as_str().chars().next().unwrap(), l.name()))
            .collect();
        assert_eq!(names, [('a', "queued"), ('c', "passed")], "{live:#?}");
        assert_eq!(lane.file.entries.len(), 2);
        assert!(lane.file.entries[1].passed.is_some());
        lane.save().unwrap();
        drop(lane);
        // After the hold, a pass no longer holds the ref; a push allowed
        // since then holds it again.
        let later = now + jiff::SignedDuration::from_secs(601);
        let mut lane = Lane::open(&d, &id, "refs/heads/main").unwrap();
        let live = lane.prune(&d, hold, later, &|_| false);
        assert_eq!(live.len(), 1, "{live:#?}");
        drop(lane);
        let mut lane = Lane::open(&d, &id, "refs/heads/main").unwrap();
        lane.upsert(cand('c', &passed));
        assert!(lane.mark_allowed(&oid('c'), later));
        assert!(!lane.mark_allowed(&oid('8'), later));
        let live = lane.prune(&d, hold, later, &|_| false);
        assert_eq!(live.len(), 2, "{live:#?}");
        lane.save().unwrap();
        drop(lane);
        // The remote check reads the entries of a job; removing them
        // frees the ref.
        assert_eq!(of_job(&d, &queued).len(), 1);
        remove_job(&d, &queued);
        assert!(of_job(&d, &queued).is_empty());
        // `status` lists the live ones; gc keeps a file with a live entry
        // and removes one without.
        let listed = live_candidates(&d, std::slice::from_ref(&id), hold);
        assert_eq!(listed.len(), 1, "{listed:#?}");
        assert!(live_candidates(&d, &["local:/elsewhere".into()], hold).is_empty());
        assert_eq!(gc(&d, hold), 0);
        remove_job(&d, &passed);
        assert_eq!(gc(&d, hold), 1);
        assert!(lane_files(&d).is_empty());
        assert_eq!(age_text(Duration::from_secs(45)), "45s");
        assert_eq!(age_text(Duration::from_secs(192)), "3m12s");
        assert_eq!(age_text(Duration::from_secs(7500)), "2h05m");
    }

    /// R111: a pass or allow time in the future (a clock that was ahead)
    /// counts as now, and is kept as now: it holds the ref for at most
    /// `candidate_hold` from the first read.
    #[test]
    fn a_time_in_the_future_holds_for_at_most_the_hold_r111() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        let hold = Duration::from_secs(600);
        let now = jiff::Timestamp::now();
        let passed = job(
            &d,
            3,
            JobState::Finished {
                verdict: Verdict::Pass,
            },
        );
        let id = identity_of("/srv/r.git");
        let mut lane = Lane::open(&d, &id, "refs/heads/main").unwrap();
        let mut c = cand('c', &passed);
        let day = jiff::SignedDuration::from_hours(24);
        c.passed = Some(now + day);
        c.allowed = Some(now + day);
        lane.upsert(c);
        assert_eq!(lane.prune(&d, hold, now, &|_| false).len(), 1);
        assert_eq!(lane.file.entries[0].passed, Some(now));
        assert_eq!(lane.file.entries[0].allowed, Some(now));
        let after = now + jiff::SignedDuration::from_secs(601);
        assert!(lane.prune(&d, hold, after, &|_| false).is_empty());
    }

    /// R111: two processes that update one ref at the same moment both
    /// keep their entry (the lock serializes the read-modify-write).
    #[test]
    fn concurrent_updates_keep_every_entry_r111() {
        let tmp = tempfile::tempdir().unwrap();
        let d = dirs(tmp.path());
        let j = job(&d, 1, JobState::Queued);
        let id = identity_of("/srv/r.git");
        std::thread::scope(|s| {
            for n in 0..8u8 {
                let (d, j, id) = (&d, &j, &id);
                s.spawn(move || {
                    let mut lane = Lane::open(d, id, "refs/heads/main").unwrap();
                    std::thread::sleep(Duration::from_millis(5));
                    lane.upsert(cand(char::from(b'0' + n), j));
                    lane.save().unwrap();
                });
            }
        });
        let lane = Lane::open(&d, &id, "refs/heads/main").unwrap();
        assert_eq!(lane.file.entries.len(), 8);
    }
}
