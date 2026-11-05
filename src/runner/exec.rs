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
    // SAFETY: killpg with the step's own group id only sends a signal.
    unsafe {
        libc::killpg(leader, libc::SIGKILL);
    }
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
    for pid in term_targets {
        let _ = procs::signal(*pid, libc::SIGTERM);
    }
    let grace_end = Instant::now() + grace;
    let mut set = live_set(leader, child, leader_reaped);
    let found = set.len().max(term_targets.len());
    while !set.is_empty() && Instant::now() < grace_end {
        std::thread::sleep(POLL);
        set = live_set(leader, child, leader_reaped);
    }
    let kill_end = Instant::now() + KILL_WAIT;
    while !set.is_empty() && Instant::now() < kill_end {
        kill_all(&set, leader);
        std::thread::sleep(POLL);
        set = live_set(leader, child, leader_reaped);
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
    spec.env
        .apply(&mut cmd)
        .args(&spec.args)
        .current_dir(spec.cwd)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(log)
        .process_group(0);
    let inherit: Vec<std::os::fd::RawFd> = spec.inherit.to_vec();
    #[cfg(target_os = "linux")]
    let parent = std::process::id();
    // SAFETY: the closure runs in the forked child before exec and calls
    // only async-signal-safe functions (prctl, getppid, raise, fcntl); it
    // reads `inherit` and `parent`, which were set up before the fork.
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
            for fd in &inherit {
                if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = match cmd.spawn() {
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
    ExecOutcome {
        end,
        duration: start.elapsed(),
        killed,
        survivors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> JobEnv {
        JobEnv::from_vars([("PATH", "/usr/bin:/bin")])
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
            args: sh("echo out; echo err >&2; exit 3"),
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
        });
        assert_eq!(out.exit_code(), Some(3));
        assert!(!out.success());
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("out") && text.contains("err"), "{text}");
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
            args: sh(&script),
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: Some(Instant::now() + Duration::from_millis(400)),
            grace: Duration::from_millis(300),
            abort: &mut never,
            inherit: &[],
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
            args: vec!["30".into()],
            cwd: tmp.path(),
            env: &env,
            log: &log,
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(5),
            abort: &mut abort,
            inherit: &[],
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
            args: Vec::new(),
            cwd: tmp.path(),
            env: &env,
            log: &tmp.path().join("l"),
            stdout: None,
            deadline: None,
            grace: Duration::from_secs(1),
            abort: &mut never,
            inherit: &[],
        });
        assert!(matches!(out.end, ExecEnd::SpawnFailed(_)));
    }
}
