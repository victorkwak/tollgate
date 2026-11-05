//! Host-wide slot semaphores with fair flock tickets (R85, R86, R87).
//!
//! A semaphore is a dir with `slot-<i>` files and a `queue/` dir. A slot is
//! held by an exclusive `flock(2)` on its file (`File::try_lock`), so the
//! kernel releases it when the holder dies, on Linux and macOS alike.
//!
//! - All-or-nothing in canonical order (R85): a caller that needs several
//!   resources takes them sorted by name; when one has no free slot it
//!   releases the ones it took and waits. No hold-and-wait, no deadlock.
//! - Fairness (R86): a waiter holds a `flock` on a ticket
//!   `queue/<priority>-<unix nanos>-<pid>-<seq>` in every queue it waits in,
//!   all with the same name, so the order is the same in every queue. It may
//!   take slots only when no older ticket is held. A ticket whose lock can be
//!   taken belongs to a dead process and is removed. There is no
//!   pid-liveness test: pids are reused.
//! - Tickets are locked before they become visible (create a dot-file, lock,
//!   rename), so a visible unlocked ticket is always a dead one.
//! - Priority (R89): hook jobs rank before `--detach` pre-warms.
//! - Verify checkouts (R41, R87): one lock file per checkout, held for the
//!   whole job; the checkouts of a tier form one semaphore.

use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

use crate::config::Tier;
use crate::dirs::{self, Dirs};
use crate::fsx;
use crate::ids::{RepoKey, ResourceName};

/// R86: poll interval of a waiter (with jitter).
pub const DEFAULT_POLL: Duration = Duration::from_millis(200);

/// An open file with an exclusive `flock`, released on drop or process death.
#[derive(Debug)]
pub struct LockFile {
    file: File,
    path: PathBuf,
}

fn open_lock_file(path: &Path) -> io::Result<File> {
    if let Some(dir) = path.parent() {
        fsx::ensure_dir(dir)?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

impl LockFile {
    /// Takes the lock on `path` (created if needed) without waiting.
    /// `Ok(None)` when another open file holds it.
    pub fn try_acquire(path: &Path) -> io::Result<Option<Self>> {
        let file = open_lock_file(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self {
                file,
                path: path.to_owned(),
            })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(e),
        }
    }

    /// Takes the lock on `path`, waiting as long as needed.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let file = open_lock_file(path)?;
        file.lock()?;
        Ok(Self {
            file,
            path: path.to_owned(),
        })
    }

    /// The lock file.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The open file (to write holder details).
    #[must_use]
    pub fn file(&self) -> &File {
        &self.file
    }

    /// The open file; the lock lives as long as it (and any duplicate) is
    /// open, so it can be handed to a child process.
    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }
}

/// True when another open file holds the lock on `path` (a missing file is
/// not held).
pub fn is_held(path: &Path) -> io::Result<bool> {
    match File::open(path) {
        Ok(f) => match f.try_lock() {
            Ok(()) => Ok(false),
            Err(TryLockError::WouldBlock) => Ok(true),
            Err(TryLockError::Error(e)) => Err(e),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// Queue rank of a waiter (R89).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    /// A hook is waiting for this job.
    Hook = 0,
    /// A `tollgate check --detach` pre-warm.
    Prewarm = 1,
}

static TICKET_SEQ: AtomicU64 = AtomicU64::new(0);

/// A ticket name: priority, then creation time, then pid and sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TicketName {
    priority: u8,
    nanos: u64,
    pid: u32,
    seq: u64,
}

impl TicketName {
    fn new(priority: Priority) -> Self {
        Self {
            priority: priority as u8,
            nanos: fsx::unix_nanos(),
            pid: std::process::id(),
            seq: TICKET_SEQ.fetch_add(1, AtomicOrdering::Relaxed),
        }
    }

    /// `<priority>-<nanos, 20 digits>-<pid>-<seq>`.
    #[must_use]
    pub fn file_name(&self) -> String {
        format!(
            "{}-{:020}-{}-{}",
            self.priority, self.nanos, self.pid, self.seq
        )
    }

    /// Parses a ticket file name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        let mut parts = name.split('-');
        let t = Self {
            priority: parts.next()?.parse().ok()?,
            nanos: parts.next()?.parse().ok()?,
            pid: parts.next()?.parse().ok()?,
            seq: parts.next()?.parse().ok()?,
        };
        parts.next().is_none().then_some(t)
    }
}

/// A counting semaphore of lock files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Semaphore {
    label: String,
    queue_dir: PathBuf,
    slots: Vec<PathBuf>,
}

impl Semaphore {
    /// `<dir>/slot-<i>` for `i < slots`, queue `<dir>/queue`.
    #[must_use]
    pub fn new(label: impl Into<String>, dir: &Path, slots: u32) -> Self {
        Self {
            label: label.into(),
            queue_dir: dir.join("queue"),
            slots: (0..slots.max(1))
                .map(|i| dir.join(format!("slot-{i}")))
                .collect(),
        }
    }

    /// A host resource: `locks/<resource>/` (R85).
    #[must_use]
    pub fn resource(dirs: &Dirs, name: &ResourceName, slots: u32) -> Self {
        Self::new(name.as_str(), &dirs.resource_lock_dir(name), slots)
    }

    /// The verify checkouts of one tier of one repo clone (R41, R87): slot
    /// `i` is the lock `wt<i>.lock` of checkout `wt<i>`.
    #[must_use]
    pub fn verify(verify_root: &Path, repo: &RepoKey, tier: Tier, slots: u32) -> Self {
        let dir = dirs::verify_tier_dir(verify_root, repo, tier);
        Self {
            label: format!("verify/{repo}/{tier}"),
            queue_dir: dir.join("queue"),
            slots: (0..slots.max(1))
                .map(|i| dir.join(format!("{}.lock", dirs::verify_checkout_name(i))))
                .collect(),
        }
    }

    /// The name used for canonical order.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The queue dir.
    #[must_use]
    pub fn queue_dir(&self) -> &Path {
        &self.queue_dir
    }

    /// The slot lock files.
    #[must_use]
    pub fn slot_paths(&self) -> &[PathBuf] {
        &self.slots
    }

    /// How many slots are held now (for `doctor` and tests).
    pub fn held_count(&self) -> io::Result<usize> {
        let mut n = 0;
        for p in &self.slots {
            if is_held(p)? {
                n += 1;
            }
        }
        Ok(n)
    }

    /// Live ticket names in the queue, oldest first. Removes dead tickets.
    pub fn waiting(&self) -> io::Result<Vec<TicketName>> {
        let mut live = Vec::new();
        for (name, path) in self.tickets()? {
            if ticket_alive(&path)? {
                live.push(name);
            }
        }
        live.sort();
        Ok(live)
    }

    fn tickets(&self) -> io::Result<Vec<(TicketName, PathBuf)>> {
        let rd = match fs::read_dir(&self.queue_dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut out = Vec::new();
        for entry in rd {
            let entry = entry?;
            let name = entry.file_name();
            if let Some(t) = name.to_str().and_then(TicketName::parse) {
                out.push((t, entry.path()));
            }
        }
        Ok(out)
    }

    fn older_ticket_alive(&self, mine: &TicketName) -> io::Result<bool> {
        for (name, path) in self.tickets()? {
            if name.cmp(mine) == Ordering::Less && ticket_alive(&path)? {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn try_take(&self) -> io::Result<Option<(u32, LockFile)>> {
        for (i, p) in self.slots.iter().enumerate() {
            if let Some(lock) = LockFile::try_acquire(p)? {
                return Ok(Some((u32::try_from(i).unwrap_or(u32::MAX), lock)));
            }
        }
        Ok(None)
    }
}

/// A ticket is alive while its owner holds the lock. A ticket that can be
/// locked is dead and is removed (R86).
fn ticket_alive(path: &Path) -> io::Result<bool> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    match file.try_lock() {
        Ok(()) => {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            Ok(false)
        }
        Err(TryLockError::WouldBlock) => Ok(true),
        Err(TryLockError::Error(e)) => Err(e),
    }
}

/// The tickets of one waiter, one per queue. Removed on drop.
struct Ticket {
    held: Vec<(PathBuf, File)>,
}

impl Ticket {
    fn enter(sems: &[&Semaphore], name: &TicketName) -> io::Result<Self> {
        let mut ticket = Self { held: Vec::new() };
        for s in sems {
            fsx::ensure_dir(&s.queue_dir)?;
            let visible = s.queue_dir.join(name.file_name());
            let hidden = s.queue_dir.join(format!(".tmp-{}", name.file_name()));
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&hidden)?;
            if let Err(e) = file.try_lock() {
                let _ = fs::remove_file(&hidden);
                return Err(match e {
                    TryLockError::WouldBlock => io::Error::other("fresh ticket is locked"),
                    TryLockError::Error(e) => e,
                });
            }
            if let Err(e) = fs::rename(&hidden, &visible) {
                let _ = fs::remove_file(&hidden);
                return Err(e);
            }
            ticket.held.push((visible, file));
        }
        Ok(ticket)
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        // Unlink while still locked, then close.
        for (path, _) in &self.held {
            let _ = fs::remove_file(path);
        }
    }
}

/// How to wait.
pub struct AcquireOptions<'a> {
    /// Queue rank (R89).
    pub priority: Priority,
    /// Poll interval; jitter of +-25 % is added (R86).
    pub poll: Duration,
    /// Give up at this time.
    pub deadline: Option<Instant>,
    /// Called before each attempt; `Some(reason)` stops the wait
    /// (cancellation, supersession, R89).
    pub abort: Option<&'a mut dyn FnMut() -> Option<String>>,
}

impl Default for AcquireOptions<'_> {
    fn default() -> Self {
        Self {
            priority: Priority::Hook,
            poll: DEFAULT_POLL,
            deadline: None,
            abort: None,
        }
    }
}

/// Error from [`acquire`].
#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    /// The deadline passed (R33 queue budget).
    #[error("no free slot before the deadline")]
    Deadline,
    /// The abort callback stopped the wait.
    #[error("wait stopped: {0}")]
    Aborted(String),
    /// A lock or queue file failed.
    #[error("lock files: {0}")]
    Io(#[from] io::Error),
}

/// One held slot.
#[derive(Debug)]
pub struct HeldSlot {
    /// Semaphore label.
    pub label: String,
    /// Slot index.
    pub index: u32,
    lock: LockFile,
}

impl HeldSlot {
    /// The slot's lock file.
    #[must_use]
    pub fn lock(&self) -> &LockFile {
        &self.lock
    }
}

/// Slots held together; released on drop.
#[derive(Debug, Default)]
pub struct Held {
    slots: Vec<HeldSlot>,
}

impl Held {
    /// The held slots in canonical order.
    #[must_use]
    pub fn slots(&self) -> &[HeldSlot] {
        &self.slots
    }

    /// The slot index held in the semaphore `label` (which verify checkout).
    #[must_use]
    pub fn index_of(&self, label: &str) -> Option<u32> {
        self.slots
            .iter()
            .find(|s| s.label == label)
            .map(|s| s.index)
    }
}

fn jittered(poll: Duration) -> Duration {
    let mut x = fsx::unix_nanos() ^ (u64::from(std::process::id()) << 32);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    let permille = 750 + (x % 501);
    poll * u32::try_from(permille).unwrap_or(1000) / 1000
}

/// Takes one slot of every semaphore in `sems`, all or nothing, in canonical
/// order, waiting fairly (R85, R86).
pub fn acquire(sems: &[Semaphore], mut opts: AcquireOptions<'_>) -> Result<Held, AcquireError> {
    let mut ordered: Vec<&Semaphore> = sems.iter().collect();
    ordered.sort_by(|a, b| a.label.cmp(&b.label));
    ordered.dedup_by(|a, b| a.label == b.label);
    if ordered.is_empty() {
        return Ok(Held::default());
    }
    let name = TicketName::new(opts.priority);
    let ticket = Ticket::enter(&ordered, &name)?;
    loop {
        if let Some(abort) = opts.abort.as_mut()
            && let Some(reason) = abort()
        {
            return Err(AcquireError::Aborted(reason));
        }
        let mut blocked = false;
        for s in &ordered {
            if s.older_ticket_alive(&name)? {
                blocked = true;
                break;
            }
        }
        if !blocked {
            let mut got = Vec::with_capacity(ordered.len());
            for s in &ordered {
                match s.try_take()? {
                    Some((index, lock)) => got.push(HeldSlot {
                        label: s.label.clone(),
                        index,
                        lock,
                    }),
                    None => break,
                }
            }
            if got.len() == ordered.len() {
                drop(ticket);
                return Ok(Held { slots: got });
            }
            // Not all free: release what was taken (no hold-and-wait).
            drop(got);
        }
        if opts.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(AcquireError::Deadline);
        }
        std::thread::sleep(jittered(opts.poll));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_names_sort_by_priority_then_time() {
        let a = TicketName::new(Priority::Prewarm);
        let b = TicketName::new(Priority::Prewarm);
        let h = TicketName::new(Priority::Hook);
        assert!(a < b);
        assert!(h < a, "a hook ticket ranks before older pre-warms");
        assert_eq!(TicketName::parse(&a.file_name()), Some(a));
        assert_eq!(TicketName::parse("x-1-2-3"), None);
        assert_eq!(TicketName::parse("0-1-2-3-4"), None);
        // Lexical order of file names matches the order.
        assert!(a.file_name() < b.file_name());
    }

    #[test]
    fn lock_file_is_exclusive_across_open_files() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("x/wt.lock");
        let first = LockFile::try_acquire(&p).unwrap().unwrap();
        assert!(LockFile::try_acquire(&p).unwrap().is_none());
        assert!(is_held(&p).unwrap());
        drop(first);
        assert!(!is_held(&p).unwrap());
        assert!(LockFile::try_acquire(&p).unwrap().is_some());
        assert!(!is_held(&tmp.path().join("missing")).unwrap());
    }

    #[test]
    fn verify_semaphore_maps_slots_to_checkouts_r41_r87() {
        let repo = RepoKey::parse("0123456789abcdef").unwrap();
        let s = Semaphore::verify(Path::new("/v"), &repo, Tier::Fast, 3);
        assert_eq!(
            s.slot_paths(),
            [
                PathBuf::from("/v/0123456789abcdef/fast/wt.lock"),
                PathBuf::from("/v/0123456789abcdef/fast/wt2.lock"),
                PathBuf::from("/v/0123456789abcdef/fast/wt3.lock"),
            ]
        );
        assert_eq!(s.queue_dir(), Path::new("/v/0123456789abcdef/fast/queue"));
    }

    #[test]
    fn deadline_and_abort_stop_a_wait_and_clean_the_queue() {
        let tmp = tempfile::tempdir().unwrap();
        let sem = Semaphore::new("cpu", &tmp.path().join("cpu"), 1);
        let held = acquire(std::slice::from_ref(&sem), AcquireOptions::default()).unwrap();
        let err = acquire(
            std::slice::from_ref(&sem),
            AcquireOptions {
                poll: Duration::from_millis(10),
                deadline: Some(Instant::now() + Duration::from_millis(60)),
                ..AcquireOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, AcquireError::Deadline), "{err}");
        let mut calls = 0;
        let mut abort = || {
            calls += 1;
            (calls > 2).then(|| "cancelled".to_owned())
        };
        let err = acquire(
            std::slice::from_ref(&sem),
            AcquireOptions {
                poll: Duration::from_millis(5),
                abort: Some(&mut abort),
                ..AcquireOptions::default()
            },
        )
        .unwrap_err();
        assert!(
            matches!(err, AcquireError::Aborted(ref r) if r == "cancelled"),
            "{err}"
        );
        assert!(sem.waiting().unwrap().is_empty());
        assert_eq!(fs::read_dir(sem.queue_dir()).unwrap().count(), 0);
        drop(held);
        assert_eq!(sem.held_count().unwrap(), 0);
    }

    #[test]
    fn all_or_nothing_releases_partial_holds_r85() {
        let tmp = tempfile::tempdir().unwrap();
        let cpu = Semaphore::new("cpu", &tmp.path().join("cpu"), 1);
        let pg = Semaphore::new("pg", &tmp.path().join("pg"), 1);
        let pg_held = acquire(std::slice::from_ref(&pg), AcquireOptions::default()).unwrap();
        let err = acquire(
            &[pg.clone(), cpu.clone()],
            AcquireOptions {
                poll: Duration::from_millis(5),
                deadline: Some(Instant::now() + Duration::from_millis(40)),
                ..AcquireOptions::default()
            },
        )
        .unwrap_err();
        assert!(matches!(err, AcquireError::Deadline));
        // The cpu slot was not kept while pg was busy.
        assert_eq!(cpu.held_count().unwrap(), 0);
        drop(pg_held);
        let both = acquire(&[pg, cpu], AcquireOptions::default()).unwrap();
        assert_eq!(
            both.slots()
                .iter()
                .map(|s| s.label.as_str())
                .collect::<Vec<_>>(),
            ["cpu", "pg"],
            "canonical order"
        );
        assert_eq!(both.index_of("pg"), Some(0));
    }
}
