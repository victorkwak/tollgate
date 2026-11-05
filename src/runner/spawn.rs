//! Starting the detached runner (R38, R88).
//!
//! The runner is `tollgate __run-job <id> --lock-fd 3`, started with
//! `setsid` (its own session, so the hook's process group and terminal
//! cannot take it down), stdio to `jobs/<id>/runner.log`, an environment
//! cleared down to what the runner needs, and the job's dedupe lock (R88)
//! as fd 3, so the lock lives exactly as long as the runner.
//!
//! argv\[0\] is set to `tollgate`: a hook started through its hard link has
//! `current_exe()` named after the hook, and the runner must not dispatch
//! as a hook (R1).

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};

use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::ids::JobId;

/// The hidden runner subcommand.
pub const RUNNER_SUBCOMMAND: &str = "__run-job";

/// The fd number the runner finds its dedupe lock on.
pub const LOCK_FD: i32 = 3;

/// Variables the runner keeps (R38: everything else is cleared). Jobs get
/// their environment from the spec (R52), not from these.
const RUNNER_ENV: &[&str] = &[
    "HOME",
    "PATH",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TZ",
    "XDG_CONFIG_HOME",
    "XDG_STATE_HOME",
    "XDG_DATA_HOME",
    "DOCKER_HOST",
    "SSH_AUTH_SOCK",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_NOSYSTEM",
    "GIT_SSH",
    "GIT_SSH_COMMAND",
    "GIT_SSH_VARIANT",
];

/// Starts the runner for `id`, handing it `lock`. Returns its pid. The
/// caller's copy of the lock is closed when `lock` drops here.
pub fn spawn(
    exe: &Path,
    dirs: &Dirs,
    id: &JobId,
    lock: File,
    env: &EnvSnapshot,
) -> io::Result<u32> {
    let job_dir = dirs.job_dir(id);
    crate::fsx::ensure_dir(&job_dir)?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(job_dir.join("runner.log"))?;
    let err = log.try_clone()?;
    let mut cmd = Command::new(exe);
    cmd.arg0("tollgate")
        .args([RUNNER_SUBCOMMAND, id.as_str(), "--lock-fd", "3"])
        .env_clear()
        .current_dir(&job_dir)
        .stdin(Stdio::null())
        .stdout(log)
        .stderr(err);
    for key in RUNNER_ENV {
        if let Some(v) = env.get(key) {
            cmd.env(key, v);
        }
    }
    let fd = lock.as_raw_fd();
    // SAFETY: the closure runs in the forked child before exec and only
    // calls async-signal-safe functions (setsid, dup2, fcntl).
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            if fd == LOCK_FD {
                // dup2 onto itself keeps FD_CLOEXEC; clear it.
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(fd, LOCK_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(lock);
    // For `status` and test cleanup; the job state carries the pid once
    // the job runs.
    let _ = std::fs::write(job_dir.join("runner.pid"), child.id().to_string());
    Ok(child.id())
}

/// Adopts the lock fd in the runner: it stays open (and locked) until the
/// returned file drops.
pub fn adopt_lock(fd: i32) -> io::Result<File> {
    use std::os::fd::FromRawFd;
    // SAFETY: F_GETFD only reads the fd flags.
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the fd is open (checked above) and owned by nobody else in
    // this process: the starter put it there for the runner.
    let file = unsafe { File::from_raw_fd(fd) };
    // Keep it from leaking into steps.
    // SAFETY: sets FD_CLOEXEC on an open fd.
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    Ok(file)
}
