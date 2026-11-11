//! Runs one setup step or step under process control (R33, R35).
//!
//! The command runs in its own process group with the job environment, stdin
//! closed and stdout/stderr appended to its log. On expiry of its limit, or
//! when the job is cancelled: SIGTERM to the leader, wait `grace`, then
//! SIGKILL every process in the group and every descendant, and wait until
//! that set is gone. With the runner as child subreaper (Linux), orphans
//! that left the group (`setsid`) are reparented to the runner and are in
//! the set too. Processes a step leaves behind after a normal exit are
//! killed the same way, so a resource slot is released only after the
//! step's processes are gone.
//!
//! Item 49: before the step can exec, the runner records its leader (pid,
//! group, start time) in `records` (`<job dir>/steps/`). The child blocks
//! in `pre_exec` on a pipe until the record is written; a runner that dies
//! first closes the pipe and the child exits before exec, so no step runs
//! unrecorded. A runner that dies later leaves the record, from which
//! `sched::reap_if_lost` finds the step on every platform (macOS has no
//! parent-death signal and no way to read another process's environment).
//! Residual: on macOS a step process that leaves the group (`setsid`,
//! `setpgid`) and is orphaned to launchd is not found.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use super::env::JobEnv;
use crate::procs::{self, ProcTable};

/// How long a SIGKILLed set may take to leave the process table before the
/// runner gives up waiting (uninterruptible sleep, for example).
const KILL_WAIT: Duration = Duration::from_secs(30);

/// Grace for processes left behind after a normal exit.
const LEFTOVER_GRACE: Duration = Duration::from_secs(2);

const POLL: Duration = Duration::from_millis(25);

/// What to run.
pub struct ExecSpec<'a> {
    /// Program (looked up on the job `PATH`).
    pub program: OsString,
    /// argv\[0\], when it is not `program` (see `steps::Invocation::arg0`).
    pub arg0: Option<OsString>,
    /// Arguments.
    pub args: Vec<OsString>,
    /// Working dir.
    pub cwd: &'a Path,
    /// Environment (R52).
    pub env: &'a JobEnv,
    /// Log file; output is appended.
    pub log: &'a Path,
    /// When set, stdout goes to this file (truncated) instead of the log.
    pub stdout: Option<&'a Path>,
    /// Kill the step at this time (R33).
    pub deadline: Option<Instant>,
    /// SIGTERM-to-SIGKILL wait (R35).
    pub grace: Duration,
    /// Called while the step runs; `Some(reason)` stops it (cancel, R89).
    pub abort: &'a mut dyn FnMut() -> Option<String>,
    /// Lock fds the step's processes inherit (resource slots, the checkout
    /// lock): a lock stays held while any process of the step lives, also
    /// when the runner itself dies (R35, R85, R87).
    pub inherit: &'a [std::os::fd::RawFd],
    /// Dir of the step records (item 49): `<job dir>/steps`.
    pub records: &'a Path,
}

/// Serializes gated spawns: while a child waits on its gate, no other
/// gated child is forked, so none holds a copy of another's release pipe
/// (a copy would keep that pipe open after the runner died).
static GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Spawns `cmd` so that it execs only after its leader is recorded in
/// `records` (item 49). The child sends its pid on one pipe, then blocks
/// reading another until the runner has written the record and releases
/// it with one byte. EOF instead (the runner died, or the record could not
/// be written) makes the child fail before exec. Returns the child and its
/// record file.
fn spawn_recorded(cmd: &mut Command, records: &Path) -> io::Result<(Child, std::path::PathBuf)> {
    use std::io::Read as _;
    use std::os::fd::AsRawFd as _;

    std::fs::create_dir_all(records)?;
    let _serial = GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Both pipes are close-on-exec: other children of this process drop
    // them at their exec.
    let (mut report_r, report_w) = io::pipe()?;
    let (release_r, mut release_w) = io::pipe()?;
    let fds = [
        report_r.as_raw_fd(),
        report_w.as_raw_fd(),
        release_r.as_raw_fd(),
        release_w.as_raw_fd(),
    ];
    // SAFETY: the closure runs in the forked child before exec and calls
    // only async-signal-safe functions (close, getpid, write, read); it
    // reads `fds`, which was set up before the fork, and allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            let [report_r, report_w, release_r, release_w] = fds;
            // The child's copies of the runner's ends: the release pipe
            // must reach EOF when the runner dies.
            libc::close(report_r);
            libc::close(release_w);
            let pid = libc::getpid().to_ne_bytes();
            let mut sent = 0;
            while sent < pid.len() {
                let n = libc::write(report_w, pid[sent..].as_ptr().cast(), pid.len() - sent);
                if n > 0 {
                    sent += n.cast_unsigned();
                } else if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                } else {
                    return Err(io::Error::from_raw_os_error(libc::EPIPE));
                }
            }
            libc::close(report_w);
            let mut byte = 0_u8;
            loop {
                let n = libc::read(release_r, (&raw mut byte).cast(), 1);
                if n == 1 {
                    return Ok(());
                }
                if n < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                // EOF: the runner died or refused to release it.
                return Err(io::Error::from_raw_os_error(libc::ECANCELED));
            }
        });
    }
    std::thread::scope(|scope| {
        // `spawn` returns only after the child execs (or fails), which
        // needs the release, so the recording runs beside it. The spawn
        // itself stays on this thread: Linux sends the parent-death signal
        // when the thread that forked the child exits.
        let recorder = scope.spawn(move || {
            let mut pid = [0_u8; 4];
            let recorded = report_r
                .read_exact(&mut pid)
                .map_err(|e| io::Error::other(format!("step gate: no pid from the child: {e}")))
                .and_then(|()| {
                    let pid = i32::from_ne_bytes(pid);
                    // SAFETY: getpgid only reads the group of a process.
                    let pgid = unsafe { libc::getpgid(pid) };
                    if pgid != pid {
                        return Err(io::Error::other(format!(
                            "step gate: child {pid} is in group {pgid}, not its own"
                        )));
                    }
                    let start_time = procs::start_time(pid)
                        .ok_or_else(|| io::Error::other("step gate: no start time of the child"))?;
                    procs::StepRecord {
                        pid,
                        pgid,
                        start_time,
                    }
                    .write(records)
                });
            let released = recorded.and_then(|path| release_w.write_all(&[1]).map(|()| path));
            // Without the byte, this drop is the EOF that stops the child.
            drop(release_w);
            released
        });
        let child = cmd.spawn();
        // The child has its copies (or was never forked): without these,
        // the recorder sees EOF when no child sends a pid.
        drop(report_w);
        drop(release_r);
        let released = recorder
            .join()
            .unwrap_or_else(|_| Err(io::Error::other("step gate: recorder panicked")));
        match (child, released) {
            (Ok(c), Ok(path)) => Ok((c, path)),
            (Ok(mut c), Err(e)) => {
                // It cannot have run without the byte; collect it.
                let _ = c.wait();
                Err(e)
            }
            (Err(e), released) => {
                if let Ok(path) = released {
                    let _ = std::fs::remove_file(path);
                }
                Err(e)
            }
        }
    })
}

/// How a step ended.
#[derive(Debug)]
pub enum ExecEnd {
    /// The leader exited by itself.
    Exited(ExitStatus),
    /// The limit expired; the step was killed.
    TimedOut,
    /// The abort callback stopped it.
    Aborted(String),
    /// The program could not be started.
    SpawnFailed(io::Error),
}

/// The outcome of [`run`].
#[derive(Debug)]
pub struct ExecOutcome {
    /// How it ended.
    pub end: ExecEnd,
    /// Wall time from spawn to the end of cleanup.
    pub duration: Duration,
    /// Processes of the step that cleanup had to stop: the set at expiry,
    /// or what was left behind after a normal exit.
    pub killed: usize,
    /// Processes that did not leave the table after SIGKILL (should be 0).
    pub survivors: usize,
}

impl ExecOutcome {
    /// The exit code when the leader exited with one.
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        match &self.end {
            ExecEnd::Exited(s) => s.code(),
            _ => None,
        }
    }

    /// True when the leader exited with status 0.
    #[must_use]
    pub fn success(&self) -> bool {
        matches!(&self.end, ExecEnd::Exited(s) if s.success())
    }
}

/// The live processes that belong to the step of `leader`.
fn step_set(table: &ProcTable, leader: i32) -> BTreeSet<i32> {
    let me = std::process::id().cast_signed();
    let mut set = table.descendants(leader);
    set.insert(leader);
    set.extend(table.group_members(leader));
    if procs::is_subreaper() {
        // Orphans of the step were reparented to this process.
        set.extend(table.descendants(me));
    }
    set.retain(|p| *p != me && table.alive(*p));
    set
}

/// Snapshot, reap adopted zombies, and return the step's live set.
fn live_set(leader: i32, child: &mut Child, leader_reaped: &mut bool) -> BTreeSet<i32> {
    if !*leader_reaped && matches!(child.try_wait(), Ok(Some(_))) {
        *leader_reaped = true;
    }
    let Ok(table) = ProcTable::snapshot() else {
        return BTreeSet::new();
    };
    if procs::is_subreaper() {
        let keep: &[i32] = if *leader_reaped { &[] } else { &[leader] };
        procs::reap_adopted_zombies(&table, keep);
    }
    let table = ProcTable::snapshot().unwrap_or(table);
    step_set(&table, leader)
}

fn kill_all(set: &BTreeSet<i32>, leader: i32) {
    for pid in set {
        let _ = procs::signal(*pid, libc::SIGKILL);
    }
    // The group too, in case a member appeared after the snapshot.
    let _ = procs::signal_group(leader, libc::SIGKILL);
}

/// SIGTERM `term_targets`, wait up to `grace` for the step's set to go,
/// then SIGKILL what is left and wait until it is gone. Returns (processes
/// alive when cleanup started, survivors).
fn terminate(
    leader: i32,
    child: &mut Child,
    leader_reaped: &mut bool,
    term_targets: &BTreeSet<i32>,
    grace: Duration,
) -> (usize, usize) {
    // Without a subreaper (macOS), a process the signal orphans reparents to
    // launchd and leaves the walk: what the walk saw before the signal stays
    // in the set.
    let before = live_set(leader, child, leader_reaped);
    let live = |child: &mut Child, leader_reaped: &mut bool| {
        let mut set = live_set(leader, child, leader_reaped);
        if !procs::is_subreaper()
            && let Ok(table) = ProcTable::snapshot()
        {
            set.extend(before.iter().filter(|p| table.alive(**p)));
        }
        set
    };
    for pid in term_targets {
        let _ = procs::signal(*pid, libc::SIGTERM);
    }
    let grace_end = Instant::now() + grace;
    let mut set = live(child, leader_reaped);
    let found = set.len().max(term_targets.len());
    while !set.is_empty() && Instant::now() < grace_end {
        std::thread::sleep(POLL);
        set = live(child, leader_reaped);
    }
    let kill_end = Instant::now() + KILL_WAIT;
    while !set.is_empty() && Instant::now() < kill_end {
        kill_all(&set, leader);
        std::thread::sleep(POLL);
        set = live(child, leader_reaped);
    }
    if !*leader_reaped {
        let _ = child.wait();
        *leader_reaped = true;
    }
    (found, set.len())
}

/// Runs the step and cleans up after it (R35).
pub fn run(spec: ExecSpec<'_>) -> ExecOutcome {
    let start = Instant::now();
    let failed = |e: io::Error| ExecOutcome {
        end: ExecEnd::SpawnFailed(e),
        duration: start.elapsed(),
        killed: 0,
        survivors: 0,
    };
    let log = match OpenOptions::new().create(true).append(true).open(spec.log) {
        Ok(f) => f,
        Err(e) => return failed(e),
    };
    let stdout = match spec.stdout {
        Some(p) => std::fs::File::create(p),
        None => log.try_clone(),
    };
    let stdout = match stdout {
        Ok(f) => f,
        Err(e) => return failed(e),
    };
    let mut cmd = Command::new(&spec.program);
    if let Some(a0) = &spec.arg0 {
        cmd.arg0(a0);
    }
    spec.env
        .apply(&mut cmd)
        .args(&spec.args)
        .current_dir(spec.cwd)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(log)
        .process_group(0);
    let inherit: Vec<std::os::fd::RawFd> = spec.inherit.to_vec();
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let parent = std::process::id();
    // SAFETY: the closure runs in the forked child before exec and calls
    // only async-signal-safe functions (prctl, getppid, raise, fcntl; on
    // macOS fork, waitpid and the watcher's system calls); it reads
    // `inherit` and `parent`, which were set up before the fork.
    unsafe {
        cmd.pre_exec(move || {
            // R35: the step leader dies with the runner (SIGKILL, OOM), and
            // a runner that died before this point leaves no orphan step.
            #[cfg(target_os = "linux")]
            {
                #[allow(clippy::cast_sign_loss)]
                let sig = libc::SIGKILL as libc::c_ulong;
                if libc::prctl(libc::PR_SET_PDEATHSIG, sig, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid().cast_unsigned() != parent {
                    libc::raise(libc::SIGKILL);
                }
            }
            #[cfg(target_os = "macos")]
            {
                let runner = parent.cast_signed();
                death_watch::start(runner)?;
                if libc::getppid() != runner {
                    libc::raise(libc::SIGKILL);
                }
            }
            for fd in &inherit {
                if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let (mut child, record) = match spawn_recorded(&mut cmd, spec.records) {
        Ok(c) => c,
        Err(e) => return failed(e),
    };
    let leader = child.id().cast_signed();
    let mut leader_reaped = false;
    let end = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                leader_reaped = true;
                break ExecEnd::Exited(status);
            }
            Ok(None) => {}
            Err(e) => break ExecEnd::SpawnFailed(e),
        }
        if spec.deadline.is_some_and(|d| Instant::now() >= d) {
            break ExecEnd::TimedOut;
        }
        if let Some(reason) = (spec.abort)() {
            break ExecEnd::Aborted(reason);
        }
        std::thread::sleep(POLL);
    };
    let (killed, survivors) = match end {
        ExecEnd::Exited(_) => {
            // Leftovers after a normal exit: same kill sequence, short grace.
            let set = live_set(leader, &mut child, &mut leader_reaped);
            if set.is_empty() {
                (0, 0)
            } else {
                terminate(leader, &mut child, &mut leader_reaped, &set, LEFTOVER_GRACE)
            }
        }
        _ => {
            // R35: SIGTERM to the leader only (nextest forwards it to its
            // tests), then the grace, then SIGKILL for the whole set.
            let leader_only: BTreeSet<i32> = [leader].into();
            terminate(
                leader,
                &mut child,
                &mut leader_reaped,
                &leader_only,
                spec.grace,
            )
        }
    };
    if (killed > 0 || survivors > 0)
        && let Ok(mut f) = OpenOptions::new().append(true).open(spec.log)
    {
        let _ = writeln!(
            f,
            "tollgate: killed {killed} process(es) of this step{}",
            if survivors > 0 {
                format!("; {survivors} did not exit after SIGKILL")
            } else {
                String::new()
            }
        );
    }
    // The step's set is gone: its record names nothing to reap. With
    // survivors it stays for a later reap.
    if survivors == 0 {
        let _ = std::fs::remove_file(&record);
    }
    ExecOutcome {
        end,
        duration: start.elapsed(),
        killed,
        survivors,
    }
}

/// macOS stand-in for the parent-death signal (R35, L13): a watcher
/// process per step that SIGKILLs the step leader when the runner exits
/// first, and ends when the leader exits.
///
/// The step's child, before exec, forks a helper that forks the watcher
/// and exits at once; the child reaps the helper, so the watcher is
/// reparented to launchd before the step execs. The helper first moves
/// to its own process group and to `/`, so the watcher is never in the
/// step's group, its descendants or its checkout: the runner's walk and
/// the bench's working-dir scan do not see it. The watcher closes every
/// inherited descriptor (no log, pipe or lock stays open through it) and
/// waits in `kevent` for `NOTE_EXIT` of the runner and of the leader. A
/// runner that is gone before the watch starts (`ESRCH`) counts as an
/// exit. Like `PR_SET_PDEATHSIG` on Linux, only the leader is signalled;
/// what else the step started is reaped from its record (item 49).
#[cfg(target_os = "macos")]
mod death_watch {
    use std::io;

    /// Starts the watcher of the calling process (the step leader) and
    /// of `runner`. Runs in the forked child before exec: only
    /// async-signal-safe system calls, no allocation.
    pub(super) fn start(runner: libc::pid_t) -> io::Result<()> {
        // SAFETY: system calls only; the forked processes never return
        // into Rust code that allocates (they end in `_exit`).
        unsafe {
            let leader = libc::getpid();
            let helper = libc::fork();
            if helper < 0 {
                return Err(io::Error::last_os_error());
            }
            if helper == 0 {
                libc::setpgid(0, 0);
                libc::chdir(c"/".as_ptr());
                let watcher = libc::fork();
                if watcher == 0 {
                    watch(runner, leader);
                }
                libc::_exit(i32::from(watcher < 0));
            }
            let mut status = 0;
            loop {
                let r = libc::waitpid(helper, &raw mut status, 0);
                if r == helper {
                    break;
                }
                if r < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    return Err(io::Error::last_os_error());
                }
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                return Err(io::Error::other("step watcher did not start"));
            }
        }
        Ok(())
    }

    /// The `NOTE_EXIT` watch of `pid` on `kq`; false when `pid` is gone.
    unsafe fn add(kq: i32, pid: libc::pid_t) -> bool {
        // SAFETY: a zeroed kevent is valid; one change, no events out.
        unsafe {
            let mut ev: libc::kevent = std::mem::zeroed();
            ev.ident = pid.cast_unsigned() as libc::uintptr_t;
            ev.filter = libc::EVFILT_PROC;
            ev.flags = libc::EV_ADD;
            ev.fflags = libc::NOTE_EXIT;
            libc::kevent(
                kq,
                &raw const ev,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            ) == 0
        }
    }

    /// The watcher: never returns.
    unsafe fn watch(runner: libc::pid_t, leader: libc::pid_t) -> ! {
        // SAFETY: system calls only, ending in `_exit`.
        unsafe {
            let mut lim: libc::rlimit = std::mem::zeroed();
            let max = if libc::getrlimit(libc::RLIMIT_NOFILE, &raw mut lim) == 0 {
                lim.rlim_cur.min(1 << 16)
            } else {
                1 << 16
            };
            for fd in 0..max {
                libc::close(i32::try_from(fd).unwrap_or(i32::MAX));
            }
            let kq = libc::kqueue();
            if kq < 0 || !add(kq, leader) {
                libc::_exit(0);
            }
            if !add(kq, runner) {
                libc::kill(leader, libc::SIGKILL);
                libc::_exit(0);
            }
            loop {
                let mut events: [libc::kevent; 2] = std::mem::zeroed();
                let n = libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    2,
                    std::ptr::null(),
                );
                if n < 0 {
                    if *libc::__error() == libc::EINTR {
                        continue;
                    }
                    libc::_exit(1);
                }
                let seen = &events[..usize::try_from(n).unwrap_or(0)];
                let gone = |pid: libc::pid_t| {
                    seen.iter()
                        .any(|e| e.ident == pid.cast_unsigned() as libc::uintptr_t)
                };
                if gone(leader) {
                    libc::_exit(0);
                }
                if gone(runner) {
                    libc::kill(leader, libc::SIGKILL);
                    libc::_exit(0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> JobEnv {
        JobEnv::from_vars([("PATH", "/usr/bin:/bin")])
    }

    /// One step-record dir for the tests of this module.
    fn records() -> &'static Path {
        static DIR: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
        DIR.get_or_init(|| tempfile::tempdir().unwrap()).path()
    }

    fn sh(script: &str) -> Vec<OsString> {
        vec!["-c".into(), script.into()]
    }

    #[test]
    fn exit_code_and_log_are_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("s.log");
        let env = env();
        let mut never = || None;
        let out = run(ExecSpec {
            program: "sh".into(),
            arg0: None,
            args: sh("echo out; echo err >&2; exit 3"),
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
            records: records(),
        });
        assert_eq!(out.exit_code(), Some(3), "{:?}", out.end);
        assert!(!out.success());
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("out") && text.contains("err"), "{text}");
    }

    #[test]
    fn arg0_is_what_the_program_sees_r1() {
        // With no operand after the script, sh's $0 is its own argv[0].
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("s.log");
        let env = env();
        let mut never = || None;
        let out = run(ExecSpec {
            program: "sh".into(),
            arg0: Some("tollgate".into()),
            args: sh("echo \"argv0=$0\""),
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
            records: records(),
        });
        assert!(out.success());
        let text = std::fs::read_to_string(&log).unwrap();
        assert_eq!(text.trim(), "argv0=tollgate", "{text}");
    }

    #[test]
    fn expiry_kills_a_term_ignoring_group_r33_r35() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("s.log");
        let pids = tmp.path().join("pids");
        let env = env();
        let mut never = || None;
        let script = format!(
            "trap '' TERM; sh -c 'trap \"\" TERM; echo $$ >> {p}; sleep 30' & echo $$ >> {p}; sleep 30",
            p = pids.display()
        );
        let start = Instant::now();
        let out = run(ExecSpec {
            program: "sh".into(),
            arg0: None,
            args: sh(&script),
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: Some(Instant::now() + Duration::from_millis(400)),
            grace: Duration::from_millis(300),
            abort: &mut never,
            inherit: &[],
            records: records(),
        });
        assert!(matches!(out.end, ExecEnd::TimedOut), "{:?}", out.end);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(out.survivors, 0);
        let table = ProcTable::snapshot().unwrap();
        for line in std::fs::read_to_string(&pids).unwrap().lines() {
            let pid: i32 = line.trim().parse().unwrap();
            assert!(!table.alive(pid), "pid {pid} survived");
        }
    }

    #[test]
    fn abort_stops_the_step_r89() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("s.log");
        let env = env();
        let mut calls = 0;
        let mut abort = || {
            calls += 1;
            (calls > 3).then(|| "cancelled".to_owned())
        };
        let out = run(ExecSpec {
            program: "sleep".into(),
            arg0: None,
            args: vec!["30".into()],
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(5),
            abort: &mut abort,
            inherit: &[],
            records: records(),
        });
        assert!(
            matches!(out.end, ExecEnd::Aborted(ref r) if r == "cancelled"),
            "{:?}",
            out.end
        );
        assert!(out.duration < Duration::from_secs(5), "sleep exits on TERM");
    }

    #[test]
    fn leftovers_after_exit_are_killed_r35() {
        let tmp = tempfile::tempdir().unwrap();
        let log = tmp.path().join("s.log");
        let pid_file = tmp.path().join("bg");
        let env = env();
        let mut never = || None;
        let out = run(ExecSpec {
            program: "sh".into(),
            arg0: None,
            args: sh(&format!(
                "sleep 30 & echo $! > {}; exit 0",
                pid_file.display()
            )),
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
            records: records(),
        });
        assert!(out.success());
        assert_eq!(out.killed, 1);
        let bg: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(!ProcTable::snapshot().unwrap().alive(bg));
    }

    #[test]
    fn missing_program_is_a_spawn_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let env = env();
        let mut never = || None;
        let out = run(ExecSpec {
            program: "tollgate-no-such-program".into(),
            arg0: None,
            args: Vec::new(),
            cwd: tmp.path(),
            env: &env,
            log: &tmp.path().join("l"),
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
            records: records(),
        });
        assert!(matches!(out.end, ExecEnd::SpawnFailed(_)));
    }
    fn run_in(tmp: &Path, records: &Path, script: &str) -> ExecOutcome {
        let env = env();
        let mut never = || None;
        run(ExecSpec {
            program: "sh".into(),
            arg0: None,
            args: sh(script),
            cwd: tmp,
            env: &env,
            log: &tmp.join("s.log"),
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
            records,
        })
    }

    /// Item 49: the leader's record (pid, own group, start time) is on
    /// disk before the step runs, and removed once its set is gone.
    #[test]
    fn a_step_runs_only_after_its_record_is_written_r35() {
        let tmp = tempfile::tempdir().unwrap();
        let recs = tmp.path().join("steps");
        let out = run_in(
            tmp.path(),
            &recs,
            &format!("cat '{}'/$$.json > seen.json", recs.display()),
        );
        assert!(out.success(), "{:?}", out.end);
        let seen: procs::StepRecord =
            serde_json::from_slice(&std::fs::read(tmp.path().join("seen.json")).unwrap()).unwrap();
        assert_eq!(seen.pgid, seen.pid);
        assert!(seen.start_time > 0);
        assert_eq!(std::fs::read_dir(&recs).unwrap().count(), 0);
    }

    /// Item 49, fail closed: when the record cannot be written the child
    /// gets EOF instead of the release byte and never execs.
    #[test]
    fn a_step_whose_record_cannot_be_written_never_runs_r35() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let recs = tmp.path().join("steps");
        std::fs::create_dir(&recs).unwrap();
        std::fs::set_permissions(&recs, std::fs::Permissions::from_mode(0o500)).unwrap();
        // Root writes into a read-only dir; the check means nothing there.
        let writable = std::fs::write(recs.join("probe"), b"").is_ok();
        let out = run_in(tmp.path(), &recs, "touch ran");
        std::fs::set_permissions(&recs, std::fs::Permissions::from_mode(0o700)).unwrap();
        if writable {
            return;
        }
        assert!(matches!(out.end, ExecEnd::SpawnFailed(_)), "{:?}", out.end);
        assert!(!tmp.path().join("ran").exists());
        // A record dir under a file: the same, before any fork.
        let out = run_in(tmp.path(), &tmp.path().join("s.log/steps"), "touch ran");
        assert!(matches!(out.end, ExecEnd::SpawnFailed(_)), "{:?}", out.end);
        assert!(!tmp.path().join("ran").exists());
    }
}
