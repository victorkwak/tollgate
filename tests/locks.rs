//! T38 (R85, R86, R87, R89): slot semaphores across real processes.
//!
//! Child processes are this test binary run again with `--exact
//! child_entry`; `TOLLGATE_TEST_CHILD` tells the child what to do. Without
//! it, `child_entry` is an empty test.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tollgate::locks::{self, AcquireOptions, LockFile, Priority, Semaphore};

const POLL: Duration = Duration::from_millis(15);

/// Kills and reaps every child on drop, so no test leaves a process behind.
struct Kids(Vec<Child>);

impl Kids {
    fn spawn(&mut self, role: &str, args: &[(&str, String)]) -> usize {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"])
            .env("TOLLGATE_TEST_CHILD", role)
            .stdin(Stdio::null())
            .stdout(Stdio::null());
        for (k, v) in args {
            cmd.env(format!("TT_{k}"), v);
        }
        self.0.push(cmd.spawn().unwrap());
        self.0.len() - 1
    }

    fn kill(&mut self, i: usize) {
        let _ = self.0[i].kill();
        let _ = self.0[i].wait();
    }

    fn wait_all(&mut self, timeout: Duration) {
        let end = Instant::now() + timeout;
        for c in &mut self.0 {
            loop {
                if c.try_wait().unwrap().is_some() {
                    break;
                }
                assert!(
                    Instant::now() < end,
                    "children did not finish in {timeout:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

impl Drop for Kids {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) {
    let end = Instant::now() + timeout;
    while !cond() {
        assert!(Instant::now() < end, "condition not met in {timeout:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// `name:slots,...` -> semaphores under `dir`.
fn sems(dir: &Path, spec: &str) -> Vec<Semaphore> {
    spec.split(',')
        .map(|r| {
            let (name, n) = r.split_once(':').unwrap();
            Semaphore::new(name, &dir.join(name), n.parse().unwrap())
        })
        .collect()
}

fn log_line(path: &Path, line: &str) {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap();
    f.write_all(format!("{line}\n").as_bytes()).unwrap();
}

fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

#[test]
fn child_entry() {
    let Ok(role) = std::env::var("TOLLGATE_TEST_CHILD") else {
        return;
    };
    let var = |k: &str| std::env::var(format!("TT_{k}")).unwrap();
    match role.as_str() {
        "hold" => {
            let dir = PathBuf::from(var("DIR"));
            let semaphores = sems(&dir, &var("RES"));
            let log = PathBuf::from(var("LOG"));
            let id = var("ID");
            let hold = Duration::from_millis(var("HOLD_MS").parse().unwrap());
            let priority = if var("PRIO") == "prewarm" {
                Priority::Prewarm
            } else {
                Priority::Hook
            };
            for _ in 0..var("REPEAT").parse::<u32>().unwrap() {
                let held = locks::acquire(
                    &semaphores,
                    AcquireOptions {
                        priority,
                        poll: POLL,
                        ..AcquireOptions::default()
                    },
                )
                .unwrap();
                log_line(&log, &format!("start {id} {}", now_ns()));
                std::thread::sleep(hold);
                log_line(&log, &format!("end {id} {}", now_ns()));
                drop(held);
            }
        }
        "lockfile" => {
            let _lock = LockFile::acquire(Path::new(&var("PATH"))).unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
        other => panic!("unknown role {other}"),
    }
    std::process::exit(0);
}

struct Ev {
    start: bool,
    id: String,
    at: u128,
}

fn events(log: &Path) -> Vec<Ev> {
    let mut ev: Vec<Ev> = std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            let mut p = l.split(' ');
            Ev {
                start: p.next() == Some("start"),
                id: p.next().unwrap().to_owned(),
                at: p.next().unwrap().parse().unwrap(),
            }
        })
        .collect();
    ev.sort_by_key(|e| (e.at, e.start));
    ev
}

fn hold_args(
    dir: &Path,
    res: &str,
    log: &Path,
    id: &str,
    hold_ms: u64,
    prio: &str,
    repeat: u32,
) -> Vec<(&'static str, String)> {
    vec![
        ("DIR", dir.display().to_string()),
        ("RES", res.to_owned()),
        ("LOG", log.display().to_string()),
        ("ID", id.to_owned()),
        ("HOLD_MS", hold_ms.to_string()),
        ("PRIO", prio.to_owned()),
        ("REPEAT", repeat.to_string()),
    ]
}

fn starts(log: &Path) -> Vec<String> {
    events(log)
        .into_iter()
        .filter(|e| e.start)
        .map(|e| e.id)
        .collect()
}

#[test]
fn six_processes_share_two_cpu_slots_r85_t38() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("log");
    let mut kids = Kids(Vec::new());
    for i in 0..6 {
        kids.spawn(
            "hold",
            &hold_args(tmp.path(), "cpu:2", &log, &format!("c{i}"), 150, "hook", 1),
        );
    }
    kids.wait_all(Duration::from_secs(20));
    let ev = events(&log);
    assert_eq!(ev.iter().filter(|e| e.start).count(), 6);
    let (mut now, mut peak) = (0i32, 0i32);
    for e in &ev {
        now += if e.start { 1 } else { -1 };
        peak = peak.max(now);
    }
    assert!(peak <= 2, "{peak} holders at once");
    assert_eq!(peak, 2, "both slots were used");
}

#[test]
fn waiters_are_served_in_ticket_order_r86_t38() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("log");
    let cpu = sems(tmp.path(), "cpu:1").remove(0);
    let held = locks::acquire(std::slice::from_ref(&cpu), AcquireOptions::default()).unwrap();
    let mut kids = Kids(Vec::new());
    for (n, id) in ["a", "b", "c"].iter().enumerate() {
        kids.spawn(
            "hold",
            &hold_args(tmp.path(), "cpu:1", &log, id, 30, "hook", 1),
        );
        wait_until(Duration::from_secs(10), || {
            cpu.waiting().unwrap().len() == n + 1
        });
    }
    drop(held);
    kids.wait_all(Duration::from_secs(10));
    assert_eq!(starts(&log), ["a", "b", "c"]);
}

#[test]
fn hooks_rank_before_prewarms_r89() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("log");
    let cpu = sems(tmp.path(), "cpu:1").remove(0);
    let held = locks::acquire(std::slice::from_ref(&cpu), AcquireOptions::default()).unwrap();
    let mut kids = Kids(Vec::new());
    kids.spawn(
        "hold",
        &hold_args(tmp.path(), "cpu:1", &log, "prewarm", 30, "prewarm", 1),
    );
    wait_until(Duration::from_secs(10), || {
        cpu.waiting().unwrap().len() == 1
    });
    kids.spawn(
        "hold",
        &hold_args(tmp.path(), "cpu:1", &log, "hook", 30, "hook", 1),
    );
    wait_until(Duration::from_secs(10), || {
        cpu.waiting().unwrap().len() == 2
    });
    drop(held);
    kids.wait_all(Duration::from_secs(10));
    assert_eq!(starts(&log), ["hook", "prewarm"]);
}

#[test]
fn killed_waiter_and_unlocked_ticket_with_live_pid_do_not_block_r86_t38() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("log");
    let cpu = sems(tmp.path(), "cpu:1").remove(0);
    let held = locks::acquire(std::slice::from_ref(&cpu), AcquireOptions::default()).unwrap();
    let mut kids = Kids(Vec::new());
    let victim = kids.spawn(
        "hold",
        &hold_args(tmp.path(), "cpu:1", &log, "victim", 30, "hook", 1),
    );
    wait_until(Duration::from_secs(10), || {
        cpu.waiting().unwrap().len() == 1
    });
    kids.spawn(
        "hold",
        &hold_args(tmp.path(), "cpu:1", &log, "next", 30, "hook", 1),
    );
    wait_until(Duration::from_secs(10), || {
        cpu.waiting().unwrap().len() == 2
    });
    // SIGKILL the older waiter: its flock goes away with it.
    kids.kill(victim);
    // An older ticket that names a live pid (as after pid reuse) but is not
    // locked: it must count as dead.
    let fake = cpu
        .queue_dir()
        .join(format!("0-{:020}-{}-0", 1, std::process::id()));
    std::fs::write(&fake, b"").unwrap();
    drop(held);
    kids.wait_all(Duration::from_secs(10));
    assert_eq!(starts(&log), ["next"]);
    assert!(!fake.exists(), "dead ticket removed");
    assert!(cpu.waiting().unwrap().is_empty());
}

#[test]
fn opposite_resource_orders_do_not_deadlock_r85_t38() {
    let tmp = tempfile::tempdir().unwrap();
    let log = tmp.path().join("log");
    let mut kids = Kids(Vec::new());
    kids.spawn(
        "hold",
        &hold_args(tmp.path(), "cpu:1,pg:1", &log, "a", 2, "hook", 15),
    );
    kids.spawn(
        "hold",
        &hold_args(tmp.path(), "pg:1,cpu:1", &log, "b", 2, "hook", 15),
    );
    kids.wait_all(Duration::from_secs(30));
    let ev = events(&log);
    assert_eq!(ev.iter().filter(|e| e.start).count(), 30);
    let (mut now, mut peak) = (0i32, 0i32);
    for e in &ev {
        now += if e.start { 1 } else { -1 };
        peak = peak.max(now);
    }
    assert_eq!(peak, 1, "cpu:1 and pg:1 admit one holder");
}

#[test]
fn verify_lock_is_released_when_its_holder_dies_r87() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tollgate::ids::RepoKey::parse("0123456789abcdef").unwrap();
    let wt = tollgate::ids::WorktreeKey::of_realpath(tmp.path());
    let path = tollgate::dirs::verify_checkout_lock(
        &tmp.path().join("v"),
        &repo,
        tollgate::config::Tier::Full,
        &wt,
    );
    let mut kids = Kids(Vec::new());
    let holder = kids.spawn("lockfile", &[("PATH", path.display().to_string())]);
    wait_until(Duration::from_secs(10), || locks::is_held(&path).unwrap());
    assert!(LockFile::try_acquire(&path).unwrap().is_none());
    kids.kill(holder);
    assert!(LockFile::try_acquire(&path).unwrap().is_some());
}
