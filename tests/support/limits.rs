//! Limits for a command a test executes after the guard allowed it.
//!
//! A security test runs, in a real shell, each command the guard does not
//! deny. A guard change can stop denying a command, so the harness must
//! be safe whatever the command is: stdin is `/dev/null` unless the test
//! gives input, each process has an address-space limit, the whole
//! process group has a wall-clock limit, and the test keeps only a
//! bounded part of the output.

use std::io::{Read, Write};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Address space of each process: an endless producer that feeds a
/// program which buffers its input ends with an allocation failure.
pub const ADDRESS_SPACE: u64 = 2 << 30;

/// Wall clock of one command (a gated commit with a real check job is
/// well below it on a busy host).
pub const WALL: Duration = Duration::from_secs(300);

/// Output kept for the test; the rest is read and dropped.
const KEEP: usize = 4 << 20;

/// Which limit ended the command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// The wall-clock limit: the process group was killed.
    WallClock,
}

/// How a limited command ended.
#[derive(Debug)]
pub struct Ended {
    /// Exit code (`None`: ended by a signal, the wall-clock kill included).
    pub code: Option<i32>,
    /// The first [`KEEP`] bytes of stdout, then of stderr.
    pub out: String,
    /// The limit that ended it, if one did.
    pub limit: Option<Limit>,
}

/// Puts the limits on `cmd`: stdin from `/dev/null`, its own process
/// group, and the address-space limit, which every process it starts
/// inherits.
pub fn apply(cmd: &mut Command) -> &mut Command {
    apply_with(cmd, ADDRESS_SPACE)
}

/// [`apply`] with `address_space` bytes.
///
/// On macOS every process starts with about 466 GiB of address space
/// reserved (the shared region and malloc's reservations), and
/// `setrlimit(RLIMIT_AS)` refuses a limit below the current size with
/// `EINVAL`. There the limit is `address_space` bytes above the size of
/// the forked child; the kernel enforces it on each new mapping after
/// `exec`, as Linux does.
pub fn apply_with(cmd: &mut Command, address_space: u64) -> &mut Command {
    cmd.stdin(Stdio::null()).process_group(0);
    // SAFETY: `setrlimit` and `proc_pidinfo` are system calls and the
    // closure allocates nothing.
    unsafe {
        cmd.pre_exec(move || {
            let limit = base_size()?.saturating_add(address_space);
            let lim = libc::rlimit {
                rlim_cur: limit as libc::rlim_t,
                rlim_max: limit as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &raw const lim) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
    }
}

/// The size the address-space limit counts from: zero on Linux.
#[cfg(not(target_os = "macos"))]
#[expect(clippy::unnecessary_wraps, reason = "the macOS form can fail")]
fn base_size() -> std::io::Result<u64> {
    Ok(0)
}

/// The size the address-space limit counts from: on macOS, the current
/// size of this (forked) process, read with no allocation.
#[cfg(target_os = "macos")]
fn base_size() -> std::io::Result<u64> {
    const SIZE: libc::c_int = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a plain C struct of `SIZE` bytes.
    let (n, info) = unsafe {
        let mut info: libc::proc_taskinfo = std::mem::zeroed();
        let n = libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDTASKINFO,
            0,
            (&raw mut info).cast(),
            SIZE,
        );
        (n, info)
    };
    if n != SIZE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(info.pti_virtual_size)
}

/// Runs `cmd` (already through [`apply`]) to its end or to `wall`, then
/// kills its process group. `input`, when given, is written to stdin.
pub fn run(cmd: &mut Command, input: Option<&[u8]>, wall: Duration) -> Ended {
    let end = Instant::now() + wall;
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn");
    let pgid = libc::pid_t::try_from(child.id()).expect("pid");
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        });
    }
    let readers = [
        drain(child.stdout.take().expect("stdout")),
        drain(child.stderr.take().expect("stderr")),
    ];
    let mut limit = None;
    let status = loop {
        if let Some(st) = child.try_wait().expect("wait") {
            break st;
        }
        if Instant::now() >= end {
            limit = Some(Limit::WallClock);
            kill_group(pgid);
            break child.wait().expect("wait");
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // A process left behind can hold the pipes open: wait for the end of
    // the output only until the limit, then kill the group. A command
    // that ended in time keeps what it left running (a check job).
    while readers.iter().any(|r| !r.lock().unwrap().1) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(5));
    }
    if readers.iter().any(|r| !r.lock().unwrap().1) {
        limit = Some(Limit::WallClock);
        kill_group(pgid);
    }
    let mut out = String::new();
    for r in &readers {
        out.push_str(&String::from_utf8_lossy(&r.lock().unwrap().0));
    }
    Ended {
        code: status.code(),
        out,
        limit,
    }
}

/// Reads `from` to its end on a thread; keeps the first [`KEEP`] bytes.
/// The flag is true at end of file.
fn drain(mut from: impl Read + Send + 'static) -> Arc<Mutex<(Vec<u8>, bool)>> {
    let kept = Arc::new(Mutex::new((Vec::new(), false)));
    let shared = Arc::clone(&kept);
    std::thread::spawn(move || {
        let mut buf = [0_u8; 64 << 10];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut k = shared.lock().unwrap();
                    let room = KEEP.saturating_sub(k.0.len());
                    k.0.extend_from_slice(&buf[..n.min(room)]);
                }
            }
        }
        shared.lock().unwrap().1 = true;
    });
    kept
}

/// SIGKILL to every process still in group `pgid` (no error when the
/// group is gone).
fn kill_group(pgid: libc::pid_t) {
    // SAFETY: `killpg` only sends a signal.
    unsafe {
        libc::killpg(pgid, libc::SIGKILL);
    }
}
