//! Runs a program at an interactive terminal: stdin (and stdout and
//! stderr, unless asked otherwise) on a new pseudo-terminal (`openpty`),
//! answering its `[y/N]` questions the way a person at the terminal would
//! (L10, item 29). Claude's Bash has no terminal, so this is how tests
//! reach what only a person may do.

#![allow(dead_code)]

use std::io::Write as _;
use std::os::fd::{FromRawFd as _, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::Run;

/// Which standard streams are the terminal.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Streams {
    /// stdin, stdout and stderr: a person at a terminal.
    All,
    /// stdin only; stdout and stderr are pipes.
    StdinOnly,
}

/// A program running on a pty.
pub struct Session {
    child: Child,
    master: std::fs::File,
    out: Arc<Mutex<Vec<u8>>>,
    readers: Vec<mpsc::Receiver<()>>,
}

fn openpty() -> (OwnedFd, OwnedFd) {
    let (mut m, mut s) = (0, 0);
    // SAFETY: openpty writes two fds into the given ints; the null name,
    // termios and winsize pointers are allowed.
    let r = unsafe {
        libc::openpty(
            &raw mut m,
            &raw mut s,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(r, 0, "openpty: {}", std::io::Error::last_os_error());
    // SAFETY: both fds were just opened and are owned here only. CLOEXEC:
    // children that other test threads start must not keep the pty open.
    unsafe {
        libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(s, libc::F_SETFD, libc::FD_CLOEXEC);
        (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s))
    }
}

/// Copies `from` into `out` until it ends (EOF, or EIO on a pty master
/// once every slave fd is closed); signals on the returned channel.
fn pump(
    mut from: impl std::io::Read + Send + 'static,
    out: &Arc<Mutex<Vec<u8>>>,
) -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    let out = Arc::clone(out);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.lock().unwrap().extend_from_slice(&buf[..n]),
            }
        }
        let _ = tx.send(());
    });
    rx
}

impl Session {
    /// Starts `cmd` (its env, cwd and args already set) on a new pty.
    pub fn spawn(mut cmd: Command, streams: Streams) -> Self {
        let (master, slave) = openpty();
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()));
        match streams {
            Streams::All => {
                cmd.stdout(Stdio::from(slave.try_clone().unwrap()))
                    .stderr(Stdio::from(slave));
            }
            Streams::StdinOnly => {
                drop(slave);
                cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
        }
        let mut child = cmd.spawn().unwrap();
        // The Command holds the slave fds; the master sees the end of the
        // output only once they are closed.
        drop(cmd);
        let out = Arc::new(Mutex::new(Vec::new()));
        let master = std::fs::File::from(master);
        let mut readers = vec![pump(master.try_clone().unwrap(), &out)];
        if let Some(o) = child.stdout.take() {
            readers.push(pump(o, &out));
        }
        if let Some(e) = child.stderr.take() {
            readers.push(pump(e, &out));
        }
        Self {
            child,
            master,
            out,
            readers,
        }
    }

    /// The output so far (`\r\n` as `\n`).
    pub fn output(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).replace("\r\n", "\n")
    }

    /// Waits until the output holds `needle` `count` times; false when the
    /// program ended or 120 s passed first.
    pub fn wait_for(&mut self, needle: &str, count: usize) -> bool {
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            if self.output().matches(needle).count() >= count {
                return true;
            }
            if Instant::now() > until || self.child.try_wait().unwrap().is_some() {
                return self.output().matches(needle).count() >= count;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Types `text` at the terminal.
    pub fn send(&mut self, text: &str) {
        self.master.write_all(text.as_bytes()).unwrap();
    }

    /// Waits for the program to end (at most 300 s) and its output.
    pub fn finish(mut self) -> Run {
        let until = Instant::now() + Duration::from_secs(300);
        let status = loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                break s;
            }
            if Instant::now() > until {
                let _ = self.child.kill();
                panic!("no exit after 300 s:\n{}", self.output());
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        // A grandchild that kept the pty open must not hang the test.
        for r in &self.readers {
            let _ = r.recv_timeout(Duration::from_secs(5));
        }
        Run {
            code: status.code(),
            out: self.output(),
        }
    }
}

/// The question every confirmation ends with.
pub const PROMPT: &str = "[y/N]";

/// Runs `cmd` on a pty and answers its questions with `answers` in order
/// (a question past the last answer gets an empty line: no).
pub fn run(cmd: Command, streams: Streams, answers: &[&str]) -> Run {
    let mut s = Session::spawn(cmd, streams);
    let mut asked = 0;
    loop {
        let done = s.child.try_wait().unwrap().is_some();
        let n = s.output().matches(PROMPT).count();
        while asked < n {
            let a = answers.get(asked).copied().unwrap_or("");
            s.send(&format!("{a}\n"));
            asked += 1;
        }
        if done {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    s.finish()
}
