//! Process-tree walk and kill for step cleanup (R35).
//!
//! - Linux: the process table comes from `/proc/<pid>/stat`; the runner can
//!   become a child subreaper (`PR_SET_CHILD_SUBREAPER`), so processes that
//!   a step orphans (a `setsid` grandchild whose parent died) are reparented
//!   to the runner and stay findable.
//! - macOS: the table comes from `proc_listallpids` and `proc_pidinfo`
//!   (`PROC_PIDTBSDINFO`) in libc. There is no subreaper: an orphan
//!   reparents to launchd, so the walk finds only what is still attached.
//!
//! The stale-lock owner check of R39 (doctor) and the parent-command lookup
//! of R13 (CUT by L1) are not here.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
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

/// SIGKILLs every process [`marked`] finds until none is left or `limit`
/// passes. Returns how many it signalled and how many were still alive at
/// the end.
pub fn kill_marked(marker: &[u8], limit: std::time::Duration) -> (usize, usize) {
    let end = std::time::Instant::now() + limit;
    let mut killed = BTreeSet::new();
    loop {
        let Ok(table) = ProcTable::snapshot() else {
            return (killed.len(), 0);
        };
        let set = marked(&table, marker);
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
    use std::fs;
    use std::io;

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

    /// True when `/proc/<pid>/environ` holds the entry `marker` exactly.
    pub(super) fn environ_has(pid: i32, marker: &[u8]) -> bool {
        fs::read(format!("/proc/{pid}/environ"))
            .is_ok_and(|env| env.split(|b| *b == 0).any(|e| e == marker))
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
    use std::io;

    use super::ProcInfo;

    /// `SZOMB` in `<sys/proc.h>`.
    const SZOMB: u32 = 5;

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
            // SAFETY: proc_bsdinfo is plain old data; zeroed is valid.
            let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
            let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
                .unwrap_or(libc::c_int::MAX);
            // SAFETY: `info` is a writable proc_bsdinfo of `size` bytes.
            let r = unsafe {
                libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
            };
            if r != size {
                continue;
            }
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

    /// No portable way to read another process's environment here.
    pub(super) fn environ_has(_pid: i32, _marker: &[u8]) -> bool {
        false
    }

    /// `pbi_start_tvsec` and `pbi_start_tvusec` of `PROC_PIDTBSDINFO`.
    pub(super) fn start_time(pid: i32) -> Option<u64> {
        // SAFETY: proc_bsdinfo is plain old data; zeroed is valid.
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let size = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).ok()?;
        // SAFETY: `info` is a writable proc_bsdinfo of `size` bytes.
        let r = unsafe {
            libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size)
        };
        (r == size).then(|| {
            info.pbi_start_tvsec
                .saturating_mul(1_000_000)
                .saturating_add(info.pbi_start_tvusec)
        })
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
}
