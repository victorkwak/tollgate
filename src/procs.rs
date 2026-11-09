//! Process-tree walk and kill for step cleanup (R35).
//!
//! - Linux: the process table comes from `/proc/<pid>/stat`; the runner can
//!   become a child subreaper (`PR_SET_CHILD_SUBREAPER`), so processes that
//!   a step orphans (a `setsid` grandchild whose parent died) are reparented
//!   to the runner and stay findable.
//! - macOS: the table comes from `proc_listallpids` and `proc_pidinfo`
//!   (`PROC_PIDTBSDINFO`) in libc, a process's arguments from
//!   `KERN_PROCARGS2`. There is no subreaper: an orphan reparents to launchd,
//!   so the walk finds only what is still attached. A dead runner's steps
//!   are found from their step records ([`StepRecord`], item 49).
//!
//! The stale-lock owner check of R39 (doctor) and the parent-command lookup
//! of R13 (CUT by L1) are not here.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

/// One process table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcInfo {
    /// Process id.
    pub pid: i32,
    /// Parent process id.
    pub ppid: i32,
    /// Process group id.
    pub pgid: i32,
    /// Exited but not reaped.
    pub zombie: bool,
}

/// A snapshot of the process table.
#[derive(Debug, Clone, Default)]
pub struct ProcTable {
    procs: BTreeMap<i32, ProcInfo>,
}

impl ProcTable {
    /// Reads the process table now.
    pub fn snapshot() -> io::Result<Self> {
        Ok(Self {
            procs: platform::list()?.into_iter().map(|p| (p.pid, p)).collect(),
        })
    }

    /// The entry of `pid`.
    #[must_use]
    pub fn get(&self, pid: i32) -> Option<&ProcInfo> {
        self.procs.get(&pid)
    }

    /// Every descendant of `root` (not `root` itself), found through parent
    /// links.
    #[must_use]
    pub fn descendants(&self, root: i32) -> BTreeSet<i32> {
        let mut children: BTreeMap<i32, Vec<i32>> = BTreeMap::new();
        for p in self.procs.values() {
            if p.pid != p.ppid {
                children.entry(p.ppid).or_default().push(p.pid);
            }
        }
        let mut out = BTreeSet::new();
        let mut stack = vec![root];
        while let Some(pid) = stack.pop() {
            for &c in children.get(&pid).map_or(&[][..], Vec::as_slice) {
                if c != root && out.insert(c) {
                    stack.push(c);
                }
            }
        }
        out
    }

    /// Every member of process group `pgid`.
    #[must_use]
    pub fn group_members(&self, pgid: i32) -> BTreeSet<i32> {
        self.procs
            .values()
            .filter(|p| p.pgid == pgid)
            .map(|p| p.pid)
            .collect()
    }

    /// True when `pid` exists and is not a zombie.
    #[must_use]
    pub fn alive(&self, pid: i32) -> bool {
        self.procs.get(&pid).is_some_and(|p| !p.zombie)
    }

    /// `pid` and every process above it, through parent links (pid 1 and
    /// the kernel's pid 0 included when the chain reaches them).
    #[must_use]
    pub fn ancestors(&self, pid: i32) -> BTreeSet<i32> {
        let mut out = BTreeSet::from([pid]);
        let mut at = pid;
        while let Some(p) = self.procs.get(&at) {
            if !out.insert(p.ppid) {
                break;
            }
            at = p.ppid;
        }
        out
    }
}

/// When process `pid` started, in a platform unit (clock ticks since boot
/// on Linux, microseconds since the epoch on macOS): with the pid, it
/// names one process, since a reused pid gets another start time.
#[must_use]
pub fn start_time(pid: i32) -> Option<u64> {
    platform::start_time(pid)
}

/// The arguments process `pid` was started with, `argv[0]` first, when they
/// can be read.
#[must_use]
pub fn argv(pid: i32) -> Option<Vec<OsString>> {
    platform::argv(pid)
}

/// The parent of process `pid`.
#[must_use]
pub fn parent_of(pid: i32) -> Option<i32> {
    platform::parent_of(pid)
}

static SUBREAPER: AtomicBool = AtomicBool::new(false);

/// Makes the calling process a child subreaper (Linux), so orphans of its
/// descendants are reparented to it (R35). Returns false where the
/// platform has no subreaper (macOS).
pub fn become_subreaper() -> io::Result<bool> {
    let on = platform::set_subreaper()?;
    SUBREAPER.store(on, Ordering::SeqCst);
    Ok(on)
}

/// True after [`become_subreaper`] succeeded in this process.
#[must_use]
pub fn is_subreaper() -> bool {
    SUBREAPER.load(Ordering::SeqCst)
}

/// Sends `signal` to `pid`. A process that is already gone is not an error.
pub fn signal(pid: i32, signal: i32) -> io::Result<()> {
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to signal pid {pid}"),
        ));
    }
    // SAFETY: kill(2) with a positive pid only sends a signal.
    if unsafe { libc::kill(pid, signal) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(e)
    }
}

/// Sends `signal` to process group `pgid`. A group that is already gone is
/// not an error. Groups 0 and 1 (the caller's own, init's) are refused.
pub fn signal_group(pgid: i32, signal: i32) -> io::Result<()> {
    if pgid <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to signal process group {pgid}"),
        ));
    }
    // SAFETY: killpg with a positive group id only sends a signal.
    if unsafe { libc::killpg(pgid, signal) } == 0 {
        return Ok(());
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(e)
    }
}

/// R35 after a runner died: the live processes (other than this one) whose
/// environment has the entry `marker` (`TMPDIR=<job dir>/tmp`, unique per
/// job, R52), plus the members of their process groups. A pid number seen
/// in a table proves nothing after reuse; the marker does. Linux reads
/// `/proc/<pid>/environ`; on macOS the set is empty (no portable way to
/// read another process's environment), so nothing is killed there.
///
/// This process and its ancestors are never in the set, and neither is any
/// process group that holds one of them. A marked process can share a
/// group with the process that started the caller (a hook that `git`
/// started in the bench's group, which is its caller's group); widening
/// to that group would kill the caller's own parents.
#[must_use]
pub fn marked(table: &ProcTable, marker: &[u8]) -> BTreeSet<i32> {
    marked_by(table, std::process::id().cast_signed(), |pid| {
        platform::environ_has(pid, marker)
    })
}

/// [`marked`] for the process `me`, with `has_marker` deciding which
/// processes carry the marker.
fn marked_by(table: &ProcTable, me: i32, has_marker: impl Fn(i32) -> bool) -> BTreeSet<i32> {
    let kept = table.ancestors(me);
    let kept_groups: BTreeSet<i32> = kept
        .iter()
        .filter_map(|p| table.get(*p).map(|i| i.pgid))
        .collect();
    let mut out: BTreeSet<i32> = table
        .procs
        .values()
        .filter(|p| !kept.contains(&p.pid) && !p.zombie && has_marker(p.pid))
        .map(|p| p.pid)
        .collect();
    let groups: BTreeSet<i32> = out
        .iter()
        .filter_map(|p| table.get(*p).map(|i| i.pgid))
        .filter(|g| !kept_groups.contains(g))
        .collect();
    for g in groups {
        out.extend(
            table
                .group_members(g)
                .into_iter()
                .filter(|p| !kept.contains(p) && table.alive(*p)),
        );
    }
    out
}

/// The working dir of process `pid`, when it can be read: Linux
/// `/proc/<pid>/cwd`, macOS `PROC_PIDVNODEPATHINFO`. Another user's
/// process has none.
#[must_use]
pub fn cwd(pid: i32) -> Option<PathBuf> {
    platform::cwd(pid)
}

/// Every value of the environment variable `key` in process `pid`
/// (Linux `/proc/<pid>/environ`; a block can hold a name twice). Empty on
/// macOS, which gives no other process's environment.
#[must_use]
pub fn environ_values(pid: i32, key: &[u8]) -> Vec<OsString> {
    platform::environ_values(pid, key)
}

/// Item 36, bench cleanup: the live processes (with the exclusions of
/// [`marked`]) whose working dir lies under one of `dirs`, or whose
/// `TMPDIR` does, plus the members of their process groups. Paths compare
/// by components, so `/s/bench-1` does not hold `/s/bench-10`.
#[must_use]
pub fn under(table: &ProcTable, dirs: &[PathBuf]) -> BTreeSet<i32> {
    let inside = |p: &Path| dirs.iter().any(|d| p.starts_with(d));
    marked_by(table, std::process::id().cast_signed(), |pid| {
        cwd(pid).is_some_and(|c| inside(&c))
            || environ_values(pid, b"TMPDIR")
                .iter()
                .any(|t| inside(Path::new(t)))
    })
}

/// R35, item 49: a step leader as the runner recorded it before the step
/// could run (`<job dir>/steps/<pid>.json`). The step runs in its own
/// process group, so `pgid` is `pid`; with `start_time` the record names
/// one process even after its pid is reused. It is how a dead runner's
/// steps are found on macOS, which has no parent-death signal and gives
/// no other process's environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StepRecord {
    /// The leader's pid.
    pub pid: i32,
    /// Its process group.
    pub pgid: i32,
    /// [`start_time`] of the leader.
    pub start_time: u64,
}

impl StepRecord {
    /// The record file of `pid` in `dir`.
    #[must_use]
    pub fn path(dir: &Path, pid: i32) -> PathBuf {
        dir.join(format!("{pid}.json"))
    }

    /// Writes the record into `dir` by rename, so a reader sees all of it
    /// or nothing. Not synced: after a reboot no recorded process lives.
    pub fn write(&self, dir: &Path) -> io::Result<PathBuf> {
        use std::io::Write as _;
        std::fs::create_dir_all(dir)?;
        let path = Self::path(dir, self.pid);
        let tmp = dir.join(format!(".{}-{}.tmp", self.pid, crate::fsx::unique_suffix()));
        let body = serde_json::to_vec(self).map_err(io::Error::other)?;
        let done = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .and_then(|mut f| f.write_all(&body))
            .and_then(|()| std::fs::rename(&tmp, &path));
        if done.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        done.map(|()| path)
    }

    /// Every readable record in `dir` (names that start with `.` are
    /// partial writes).
    #[must_use]
    pub fn read_all(dir: &Path) -> Vec<Self> {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter(|e| !e.file_name().as_encoded_bytes().starts_with(b"."))
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok())
            .collect()
    }
}

/// R35 after a runner died: the live processes of the recorded steps,
/// with the exclusions of [`marked`].
///
/// - The leader still runs with its recorded start time: it, its group
///   and every descendant of either.
/// - The leader is gone (or a zombie): the members of its group that
///   started no earlier than it did, and their descendants. Its pid
///   cannot have been reused while the group had a member, so a group of
///   that id is the step's, unless the group emptied, the pid was reused
///   and the new process made a group of its own; the start-time bound
///   leaves out what predates the step.
/// - The pid runs another process (another start time): the group is
///   gone with its last member; nothing is taken.
#[must_use]
pub fn recorded(table: &ProcTable, records: &[StepRecord]) -> BTreeSet<i32> {
    recorded_by(table, std::process::id().cast_signed(), records, start_time)
}

/// [`recorded`] for the process `me`, with `start_of` giving start times.
fn recorded_by(
    table: &ProcTable,
    me: i32,
    records: &[StepRecord],
    start_of: impl Fn(i32) -> Option<u64>,
) -> BTreeSet<i32> {
    let kept = table.ancestors(me);
    let kept_groups: BTreeSet<i32> = kept
        .iter()
        .filter_map(|p| table.get(*p).map(|i| i.pgid))
        .collect();
    let mut out = BTreeSet::new();
    for r in records {
        if r.pid <= 1 || r.pgid <= 1 || kept_groups.contains(&r.pgid) {
            continue;
        }
        let leader_runs = match (table.get(r.pid), start_of(r.pid)) {
            (None, _) => false,
            (Some(_), Some(t)) if t == r.start_time => true,
            (Some(p), None) if p.zombie => false,
            // Another process has the pid, or its start time is unreadable
            // (another user's).
            (Some(_), _) => continue,
        };
        let mut roots: BTreeSet<i32> = table
            .group_members(r.pgid)
            .into_iter()
            .filter(|m| leader_runs || start_of(*m).is_some_and(|t| t >= r.start_time))
            .collect();
        if leader_runs {
            roots.insert(r.pid);
        }
        let mut set = roots.clone();
        for root in &roots {
            set.extend(table.descendants(*root));
        }
        out.extend(
            set.into_iter()
                .filter(|p| *p != me && !kept.contains(p) && table.alive(*p)),
        );
    }
    out
}

/// SIGKILLs every process [`recorded`] finds, like [`kill_marked`].
pub fn kill_recorded(records: &[StepRecord], limit: std::time::Duration) -> (usize, usize) {
    if records.is_empty() {
        return (0, 0);
    }
    kill_found(limit, |table| recorded(table, records))
}

/// SIGKILLs every process [`under`] finds, like [`kill_marked`].
pub fn kill_under(dirs: &[PathBuf], limit: std::time::Duration) -> (usize, usize) {
    kill_found(limit, |table| under(table, dirs))
}

/// SIGKILLs every process [`marked`] finds until none is left or `limit`
/// passes. Returns how many it signalled and how many were still alive at
/// the end.
pub fn kill_marked(marker: &[u8], limit: std::time::Duration) -> (usize, usize) {
    kill_found(limit, |table| marked(table, marker))
}

/// SIGKILLs every process `find` returns until it returns none or `limit`
/// passes. Returns how many it signalled and how many were still alive at
/// the end.
fn kill_found(
    limit: std::time::Duration,
    find: impl Fn(&ProcTable) -> BTreeSet<i32>,
) -> (usize, usize) {
    let end = std::time::Instant::now() + limit;
    let mut killed = BTreeSet::new();
    loop {
        let Ok(table) = ProcTable::snapshot() else {
            return (killed.len(), 0);
        };
        let set = find(&table);
        if set.is_empty() || std::time::Instant::now() >= end {
            return (killed.len(), set.len());
        }
        for pid in set {
            let _ = signal(pid, libc::SIGKILL);
            killed.insert(pid);
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// Reaps `pid` when it is a zombie child of this process. Returns true when
/// it was reaped.
pub fn reap_if_zombie(pid: i32) -> bool {
    let mut status = 0;
    // SAFETY: waitpid with WNOHANG on one pid; `status` is a valid out
    // pointer. It reaps only that pid, and only when it has exited.
    let r = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
    r == pid
}

/// Reaps every zombie whose parent is this process, except `keep` (a child
/// whose status a `std::process::Child` still has to collect). A subreaper
/// must do this, or orphans it adopted never leave the table.
pub fn reap_adopted_zombies(table: &ProcTable, keep: &[i32]) {
    let me = std::process::id().cast_signed();
    for p in table.procs.values() {
        if p.ppid == me && p.zombie && !keep.contains(&p.pid) {
            reap_if_zombie(p.pid);
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::io;
    use std::os::unix::ffi::OsStrExt as _;

    use super::ProcInfo;

    /// Parses `/proc/<pid>/stat`: `pid (comm) state ppid pgrp ...`. `comm`
    /// may hold spaces and parentheses, so fields are read after the last
    /// `)`.
    pub(super) fn parse_stat(text: &str) -> Option<ProcInfo> {
        let open = text.find('(')?;
        let close = text.rfind(')')?;
        let pid = text[..open].trim().parse().ok()?;
        let mut rest = text[close + 1..].split_whitespace();
        let state = rest.next()?;
        let ppid = rest.next()?.parse().ok()?;
        let pgid = rest.next()?.parse().ok()?;
        Some(ProcInfo {
            pid,
            ppid,
            pgid,
            zombie: state == "Z" || state == "X",
        })
    }

    pub(super) fn list() -> io::Result<Vec<ProcInfo>> {
        let mut out = Vec::new();
        for entry in fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
                continue;
            };
            // A process can exit between readdir and read.
            let Ok(text) = fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            if let Some(p) = parse_stat(&text).filter(|p| p.pid == pid) {
                out.push(p);
            }
        }
        Ok(out)
    }

    /// Parses `/proc/<pid>/cmdline`: each argument ends with a NUL, and an
    /// empty argument is an argument. An empty block (a zombie, a kernel
    /// thread, or a process inside `execve` before the kernel wrote its
    /// arguments) is None.
    pub(super) fn parse_cmdline(bytes: &[u8]) -> Option<Vec<OsString>> {
        if bytes.is_empty() {
            return None;
        }
        let body = bytes.strip_suffix(&[0]).unwrap_or(bytes);
        Some(
            body.split(|b| *b == 0)
                .map(|a| OsStr::from_bytes(a).to_owned())
                .collect(),
        )
    }

    pub(super) fn argv(pid: i32) -> Option<Vec<OsString>> {
        parse_cmdline(&fs::read(format!("/proc/{pid}/cmdline")).ok()?)
    }

    pub(super) fn parent_of(pid: i32) -> Option<i32> {
        let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        parse_stat(&text).map(|p| p.ppid)
    }

    /// True when `/proc/<pid>/environ` holds the entry `marker` exactly.
    pub(super) fn environ_has(pid: i32, marker: &[u8]) -> bool {
        fs::read(format!("/proc/{pid}/environ"))
            .is_ok_and(|env| env.split(|b| *b == 0).any(|e| e == marker))
    }

    /// The values of `key` in `/proc/<pid>/environ`.
    pub(super) fn environ_values(pid: i32, key: &[u8]) -> Vec<OsString> {
        let Ok(env) = fs::read(format!("/proc/{pid}/environ")) else {
            return Vec::new();
        };
        env.split(|b| *b == 0)
            .filter_map(|e| e.strip_prefix(key)?.strip_prefix(b"="))
            .map(|v| OsStr::from_bytes(v).to_owned())
            .collect()
    }

    /// The `/proc/<pid>/cwd` link. A dir removed since reads as
    /// `<path> (deleted)`, which is still under the dir that held it.
    pub(super) fn cwd(pid: i32) -> Option<std::path::PathBuf> {
        fs::read_link(format!("/proc/{pid}/cwd")).ok()
    }

    /// Field 22 of `/proc/<pid>/stat` (`starttime`, 20th after the comm).
    pub(super) fn start_time(pid: i32) -> Option<u64> {
        let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        text[text.rfind(')')? + 1..]
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()
    }

    pub(super) fn set_subreaper() -> io::Result<bool> {
        // SAFETY: prctl(PR_SET_CHILD_SUBREAPER, 1) changes only how orphans
        // of this process's descendants are reparented.
        let r = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
        if r == 0 {
            Ok(true)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{OsStr, OsString};
    use std::io;
    use std::os::unix::ffi::OsStrExt as _;

    use super::ProcInfo;

    /// `SZOMB` in `<sys/proc.h>`.
    const SZOMB: u32 = 5;

    /// `PROC_PIDTBSDINFO` of `pid`.
    fn bsd_info(pid: i32) -> Option<libc::proc_bsdinfo> {
        // SAFETY: proc_bsdinfo is plain old data; zeroed is valid.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: `info` is a writable proc_bsdinfo of `size` bytes.
        let r = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        (r == size).then_some(info)
    }

    /// The `KERN_PROCARGS2` block of `pid`. Another user's process, or one
    /// that has exited, has none.
    fn procargs(pid: i32) -> Option<Vec<u8>> {
        let mut max: libc::c_int = 0;
        let mut size = std::mem::size_of::<libc::c_int>();
        let mut name = [libc::CTL_KERN, libc::KERN_ARGMAX];
        // SAFETY: `max` is a writable c_int and `size` holds its size.
        let r = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                2,
                (&raw mut max).cast(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return None;
        }
        let mut block = vec![0_u8; usize::try_from(max).ok()?];
        let mut size = block.len();
        let mut name = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
        // SAFETY: `block` is writable for `size` bytes.
        let r = unsafe {
            libc::sysctl(
                name.as_mut_ptr(),
                3,
                block.as_mut_ptr().cast(),
                &raw mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if r != 0 {
            return None;
        }
        block.truncate(size);
        Some(block)
    }

    /// The arguments in a `KERN_PROCARGS2` block: `argc` as a `c_int`, the
    /// executable path, NUL padding, then `argc` NUL-terminated arguments.
    pub(super) fn parse_procargs(block: &[u8]) -> Option<Vec<&[u8]>> {
        let (argc, rest) = block.split_first_chunk::<4>()?;
        let argc = usize::try_from(libc::c_int::from_ne_bytes(*argc)).ok()?;
        let padding = &rest[rest.iter().position(|b| *b == 0)?..];
        let strings = &padding[padding.iter().position(|b| *b != 0)?..];
        let args: Vec<&[u8]> = strings.split(|b| *b == 0).take(argc).collect();
        (args.len() == argc).then_some(args)
    }

    pub(super) fn argv(pid: i32) -> Option<Vec<OsString>> {
        let block = procargs(pid)?;
        Some(
            parse_procargs(&block)?
                .into_iter()
                .map(|a| OsStr::from_bytes(a).to_owned())
                .collect(),
        )
    }

    pub(super) fn parent_of(pid: i32) -> Option<i32> {
        i32::try_from(bsd_info(pid)?.pbi_ppid).ok()
    }

    pub(super) fn list() -> io::Result<Vec<ProcInfo>> {
        // SAFETY: a null buffer asks only for the needed size in bytes.
        let bytes = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if bytes <= 0 {
            return Err(io::Error::last_os_error());
        }
        let cap = usize::try_from(bytes).unwrap_or(0) / std::mem::size_of::<libc::c_int>() + 64;
        let mut pids: Vec<libc::c_int> = vec![0; cap];
        let buf_bytes = libc::c_int::try_from(cap * std::mem::size_of::<libc::c_int>())
            .map_err(|_| io::Error::other("pid buffer too large"))?;
        // SAFETY: `pids` has room for `buf_bytes` bytes.
        let n = unsafe { libc::proc_listallpids(pids.as_mut_ptr().cast(), buf_bytes) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        pids.truncate(usize::try_from(n).unwrap_or(0).min(cap));
        let mut out = Vec::new();
        for pid in pids.into_iter().filter(|p| *p > 0) {
            let Some(info) = bsd_info(pid) else { continue };
            out.push(ProcInfo {
                pid,
                ppid: i32::try_from(info.pbi_ppid).unwrap_or(0),
                pgid: i32::try_from(info.pbi_pgid).unwrap_or(0),
                zombie: info.pbi_status == SZOMB,
            });
        }
        Ok(out)
    }

    pub(super) fn set_subreaper() -> io::Result<bool> {
        Ok(false)
    }

    /// `KERN_PROCARGS2` has no environment for an unprivileged caller (`ps e`
    /// shows none either), so marked processes cannot be found here.
    pub(super) fn environ_has(_pid: i32, _marker: &[u8]) -> bool {
        false
    }

    /// See [`environ_has`].
    pub(super) fn environ_values(_pid: i32, _key: &[u8]) -> Vec<OsString> {
        Vec::new()
    }

    /// `pvi_cdir` of `PROC_PIDVNODEPATHINFO`: a NUL-terminated path of at
    /// most `MAXPATHLEN` bytes.
    pub(super) fn cwd(pid: i32) -> Option<std::path::PathBuf> {
        // SAFETY: proc_vnodepathinfo is plain old data; zeroed is valid.
        let mut info: libc::proc_vnodepathinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_vnodepathinfo>()).ok()?;
        // SAFETY: `info` is a writable proc_vnodepathinfo of `size` bytes.
        let r = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDVNODEPATHINFO,
                0,
                (&raw mut info).cast(),
                size,
            )
        };
        if r != size {
            return None;
        }
        // libc spells `vip_path[MAXPATHLEN]` as 32 rows of 32.
        let bytes: Vec<u8> = info
            .pvi_cdir
            .vip_path
            .iter()
            .flatten()
            .map(|c| c.cast_unsigned())
            .take_while(|b| *b != 0)
            .collect();
        (!bytes.is_empty()).then(|| OsStr::from_bytes(&bytes).to_owned().into())
    }

    /// `pbi_start_tvsec` and `pbi_start_tvusec` of `PROC_PIDTBSDINFO`.
    pub(super) fn start_time(pid: i32) -> Option<u64> {
        let info = bsd_info(pid)?;
        Some(
            info.pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn table(rows: &[(i32, i32, i32)]) -> ProcTable {
        ProcTable {
            procs: rows
                .iter()
                .map(|&(pid, ppid, pgid)| {
                    (
                        pid,
                        ProcInfo {
                            pid,
                            ppid,
                            pgid,
                            zombie: false,
                        },
                    )
                })
                .collect(),
        }
    }

    /// The bench (200) runs in its caller's group (100). A hook (300) that
    /// git left behind is in that group too and carries the marker. The
    /// hook dies; the caller (100), the bench and an unmarked neighbour in
    /// the group (500) do not. A step group (400) is still widened to its
    /// unmarked child (401). A marked ancestor is never in the set.
    #[test]
    fn the_callers_group_and_ancestors_are_never_marked_r35() {
        let t = table(&[
            (1, 0, 1),
            (100, 1, 100),
            (200, 100, 100),
            (300, 1, 100),
            (400, 1, 400),
            (401, 400, 400),
            (500, 100, 100),
        ]);
        assert_eq!(t.ancestors(200), BTreeSet::from([0, 1, 100, 200]));
        let marks = [100, 300, 400];
        let set = marked_by(&t, 200, |p| marks.contains(&p));
        assert_eq!(set, BTreeSet::from([300, 400, 401]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stat_lines_with_odd_comm_parse() {
        let p = platform::parse_stat("42 (a b) c)) S 7 42 42 0 -1").unwrap();
        assert_eq!((p.pid, p.ppid, p.pgid, p.zombie), (42, 7, 42, false));
        assert!(platform::parse_stat("9 (x) Z 1 9 9").unwrap().zombie);
        assert!(platform::parse_stat("garbage").is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn procargs_blocks_parse() {
        let block = |rest: &[u8]| [2_i32.to_ne_bytes().as_slice(), rest].concat();
        let full = block(b"/bin/sleep\0\0\0sleep\x005\0A=1\0\0");
        assert_eq!(
            platform::parse_procargs(&full).unwrap(),
            [b"sleep".as_slice(), b"5"]
        );
        // An empty argument is an argument; an empty block is not a process.
        let empty_arg = block(b"/bin/sh\0sh\0\0");
        assert_eq!(
            platform::parse_procargs(&empty_arg).unwrap(),
            [b"sh".as_slice(), b""]
        );
        assert!(platform::parse_procargs(b"").is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cmdline_blocks_parse() {
        let parse = |b: &[u8]| platform::parse_cmdline(b);
        assert_eq!(
            parse(b"git\0commit\0-m\0\0--allow-empty-message\0").unwrap(),
            ["git", "commit", "-m", "", "--allow-empty-message"]
        );
        // A last argument without its NUL (a process that rewrote its
        // arguments) is still read.
        assert_eq!(parse(b"sh\0-c").unwrap(), ["sh", "-c"]);
        // An empty block is a zombie, a kernel thread, or a process inside
        // execve before the kernel wrote its arguments: not readable.
        assert!(parse(b"").is_none());
    }

    #[test]
    fn a_processes_arguments_and_parent_read_back() {
        // `sh` keeps its own arguments while `sleep` runs, and the empty one
        // is an argument too.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30; :", "tg-test", "", "y"])
            .process_group(0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id().cast_signed();
        // On Linux the spawn (a vfork) returns when execve releases the
        // parent's memory, before the child switches to its new memory: for
        // a moment the child shows this test's arguments, then none (`argv`
        // is None), then its own.
        let end = Instant::now() + Duration::from_secs(5);
        let args = loop {
            let a = argv(pid);
            if let Some(a) = &a
                && a[0].to_string_lossy().ends_with("sh")
            {
                break a.clone();
            }
            assert!(Instant::now() < end, "arguments of {pid}: {a:?}");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(args[1..], ["-c", "sleep 30; :", "tg-test", "", "y"]);
        assert_eq!(parent_of(pid), Some(std::process::id().cast_signed()));
        signal_group(pid, libc::SIGKILL).unwrap();
        child.wait().unwrap();
        assert!(argv(pid).is_none());
    }

    #[test]
    fn descendants_of_a_shell_tree_r35() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30 & sleep 30 & wait"])
            .stdin(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id().cast_signed();
        let end = Instant::now() + Duration::from_secs(5);
        let table = loop {
            let t = ProcTable::snapshot().unwrap();
            if t.descendants(pid).len() >= 2 || Instant::now() > end {
                break t;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let kids = table.descendants(pid);
        assert_eq!(kids.len(), 2, "{kids:?}");
        assert!(table.group_members(pid).is_superset(&kids));
        assert!(table.alive(pid));
        for k in &kids {
            signal(*k, libc::SIGKILL).unwrap();
        }
        signal(pid, libc::SIGKILL).unwrap();
        child.wait().unwrap();
        // Signalling a reaped pid is not an error.
        assert!(signal(i32::MAX - 1, libc::SIGTERM).is_ok());
        assert!(signal(0, libc::SIGTERM).is_err());
    }
    /// Item 36: a process is under a dir by its working dir (any platform)
    /// or its `TMPDIR` (Linux), compared by path components; a sibling
    /// whose name only starts with the dir's name is not under it.
    #[test]
    fn processes_under_a_dir_by_cwd_and_tmpdir() {
        let base = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(base.path()).unwrap();
        let dir = base.join("bench");
        let sibling = base.join("bench0");
        std::fs::create_dir_all(dir.join("wt")).unwrap();
        std::fs::create_dir_all(&sibling).unwrap();
        let spawn = |cwd: &Path, tmp: &Path| {
            Command::new("sleep")
                .arg("30")
                .current_dir(cwd)
                .env("TMPDIR", tmp)
                .stdin(Stdio::null())
                .process_group(0)
                .spawn()
                .unwrap()
        };
        let mut by_cwd = spawn(&dir.join("wt"), Path::new("/tmp"));
        let mut by_tmp = spawn(Path::new("/"), &dir.join("state/jobs/j/tmp"));
        let mut outside = spawn(&sibling, &sibling);
        let pids = [&by_cwd, &by_tmp, &outside].map(|c| c.id().cast_signed());
        // The spawn returns after exec, and chdir comes before exec.
        assert_eq!(cwd(pids[0]).as_deref(), Some(dir.join("wt").as_path()));
        let set = under(&ProcTable::snapshot().unwrap(), std::slice::from_ref(&dir));
        assert!(set.contains(&pids[0]), "{set:?}");
        assert_eq!(set.contains(&pids[1]), cfg!(target_os = "linux"), "{set:?}");
        assert!(!set.contains(&pids[2]), "{set:?}");
        assert!(!set.contains(&std::process::id().cast_signed()));
        for c in [&mut by_cwd, &mut by_tmp, &mut outside] {
            let _ = c.kill();
            c.wait().unwrap();
        }
    }
    /// Item 49: a recorded step is found by its leader (pid and start time
    /// match), by its group when the leader is gone (members no older than
    /// the leader), and not at all when the pid runs another process.
    #[test]
    fn recorded_steps_are_found_by_leader_group_and_start_time_r35() {
        // 200 is the caller; 600 a step leader with a child 601 in its
        // group and a grandchild 602 that left the group.
        let t = table(&[
            (1, 0, 1),
            (100, 1, 100),
            (200, 100, 100),
            (600, 1, 600),
            (601, 600, 600),
            (602, 601, 602),
            (700, 1, 700),
        ]);
        let starts = |p: i32| -> Option<u64> {
            Some(match p {
                600 => 50,
                601 => 51,
                602 => 52,
                700 => 10,
                _ => 1,
            })
        };
        let rec = |pid, start_time| StepRecord {
            pid,
            pgid: pid,
            start_time,
        };
        // Leader alive with its start time: leader, group, descendants.
        assert_eq!(
            recorded_by(&t, 200, &[rec(600, 50)], starts),
            BTreeSet::from([600, 601, 602])
        );
        // Same pid, other start time: pid reused, nothing.
        assert_eq!(
            recorded_by(&t, 200, &[rec(600, 49)], starts),
            BTreeSet::new()
        );
        // Leader gone: the group members no older than it, and below them.
        let gone = table(&[
            (1, 0, 1),
            (100, 1, 100),
            (200, 100, 100),
            (601, 1, 600),
            (602, 601, 602),
            (603, 1, 600),
        ]);
        let starts_gone = |p: i32| -> Option<u64> {
            Some(match p {
                601 => 51,
                602 => 52,
                603 => 5,
                _ => 1,
            })
        };
        assert_eq!(
            recorded_by(&gone, 200, &[rec(600, 50)], starts_gone),
            BTreeSet::from([601, 602])
        );
        // The caller's own group and ancestors are never taken.
        assert_eq!(
            recorded_by(&t, 200, &[rec(100, 1)], starts),
            BTreeSet::new()
        );
        let r = StepRecord {
            pid: 600,
            pgid: 1,
            start_time: 50,
        };
        assert_eq!(recorded_by(&t, 200, &[r], starts), BTreeSet::new());
    }

    #[test]
    fn step_records_round_trip_and_skip_partial_writes() {
        let dir = tempfile::tempdir().unwrap();
        let steps = dir.path().join("steps");
        assert!(StepRecord::read_all(&steps).is_empty());
        let r = StepRecord {
            pid: 42,
            pgid: 42,
            start_time: 7,
        };
        let path = r.write(&steps).unwrap();
        assert_eq!(path, steps.join("42.json"));
        std::fs::write(steps.join(".43-x.tmp"), b"{").unwrap();
        std::fs::write(steps.join("44.json"), b"not json").unwrap();
        assert_eq!(StepRecord::read_all(&steps), [r]);
    }
}
