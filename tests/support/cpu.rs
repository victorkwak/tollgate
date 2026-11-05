//! CPU time of the process trees a test starts (L19).
//!
//! Wall-clock time of a hook depends on how busy the host is: at load 30 on
//! 16 threads a 3 ms hook takes 30 ms, though it does the same work. The
//! CPU time (user + system) of the hook and of every process it starts
//! changes little with load, so the L19 tests assert it, and the bench
//! (L20) measures wall-clock time under real concurrent commits.
//!
//! `getrusage(RUSAGE_CHILDREN)` counts children that were waited for, and
//! their waited descendants. A gate hook starts its runner detached
//! (`setsid`, never waited by the hook), so on Linux the test process is a
//! child subreaper (`PR_SET_CHILD_SUBREAPER`): the orphaned runner is
//! reparented to it, and [`CpuMeter::measure`] reaps it before it reads the
//! counter. Other systems have no subreaper; there the runner's share is
//! not counted.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// One measured run.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Wall-clock time of the call (load-dependent; printed only).
    pub wall: Duration,
    /// CPU time of every process the call started, reaped orphans included.
    pub cpu: Duration,
}

/// Serializes the meters of one test binary: the counter and `waitpid(-1)`
/// are per process, and `cargo test` runs tests on threads.
static METER: Mutex<()> = Mutex::new(());

/// Measures the CPU time of child process trees. Holds a process-wide lock
/// while it lives, so no other test thread starts or waits for children.
pub struct CpuMeter {
    _lock: MutexGuard<'static, ()>,
}

impl CpuMeter {
    #[must_use]
    pub fn new() -> Self {
        let lock = METER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        #[cfg(target_os = "linux")]
        {
            // SAFETY: prctl with integer arguments only.
            let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
            assert_eq!(
                rc,
                0,
                "PR_SET_CHILD_SUBREAPER: {}",
                std::io::Error::last_os_error()
            );
        }
        reap_all();
        Self { _lock: lock }
    }

    /// Runs `f`, waits until every process it started has exited (orphans
    /// too), and returns its wall and CPU time.
    pub fn measure(&self, f: impl FnOnce()) -> Sample {
        reap_all();
        let before = children_cpu();
        let start = Instant::now();
        f();
        let wall = start.elapsed();
        reap_all();
        Sample {
            wall,
            cpu: children_cpu().saturating_sub(before),
        }
    }
}

impl Default for CpuMeter {
    fn default() -> Self {
        Self::new()
    }
}

/// User plus system time of the waited-for children of this process.
fn children_cpu() -> Duration {
    // SAFETY: getrusage fills the struct it is given.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: valid pointer to a rusage struct.
    let rc = unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &raw mut ru) };
    assert_eq!(rc, 0, "getrusage: {}", std::io::Error::last_os_error());
    let tv = |t: libc::timeval| {
        Duration::from_secs(u64::try_from(t.tv_sec).unwrap())
            + Duration::from_micros(u64::try_from(t.tv_usec).unwrap())
    };
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

/// Waits for every child of this process (orphans reparented to it
/// included) until none is left. A child alive after 60 s fails the test:
/// a runner that does not end is a bug, not a slow host.
fn reap_all() {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let mut status = 0;
        // SAFETY: waitpid with a valid status pointer.
        let pid = unsafe { libc::waitpid(-1, &raw mut status, libc::WNOHANG) };
        if pid > 0 {
            continue;
        }
        if pid < 0 {
            let e = std::io::Error::last_os_error();
            assert_eq!(e.raw_os_error(), Some(libc::ECHILD), "waitpid: {e}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "a child of the test still runs after 60 s"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}
