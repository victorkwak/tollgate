//! T39 (R88, R89): job dedupe, waiters, supersession and cancel, with real
//! child processes holding the locks (this binary run again with `--exact
//! child_entry`).

mod support;

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use support::Sandbox;
use tollgate::cache::record::Verdict;
use tollgate::config::Tier;
use tollgate::dirs::Dirs;
use tollgate::env::EnvSnapshot;
use tollgate::gitx::Oid;
use tollgate::ids::{JobId, RecordKey};
use tollgate::locks::Priority;
use tollgate::sched::{
    self, CancelOutcome, Claim, JobMeta, JobState, JobStore, Origin, StateKind, Transition,
};

struct Kids(Vec<Child>);

impl Kids {
    fn spawn(&mut self, role: &str, args: &[(&str, &str)]) -> usize {
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

fn dirs_at(state: &Path) -> Dirs {
    Dirs::from_env(&EnvSnapshot::from_pairs([
        ("HOME", state.as_os_str()),
        ("XDG_STATE_HOME", state.as_os_str()),
    ]))
    .unwrap()
}

#[test]
fn child_entry() {
    let Ok(role) = std::env::var("TOLLGATE_TEST_CHILD") else {
        return;
    };
    let var = |k: &str| std::env::var(format!("TT_{k}")).unwrap();
    let dirs = dirs_at(Path::new(&var("STATE")));
    match role.as_str() {
        "claim" => {
            let key = RecordKey::parse(&var("KEY")).unwrap();
            let job = JobId::parse(&var("JOB")).unwrap();
            let Claim::Owner(claim) = sched::claim_job(&dirs, &key, &job).unwrap() else {
                panic!("child expected to own the key");
            };
            std::thread::sleep(Duration::from_secs(60));
            drop(claim);
        }
        "wait" => {
            let job = JobId::parse(&var("JOB")).unwrap();
            let _w = sched::register_waiter(&dirs.job_dir(&job)).unwrap();
            std::thread::sleep(Duration::from_secs(60));
        }
        other => panic!("unknown role {other}"),
    }
    std::process::exit(0);
}

fn key(n: u8) -> RecordKey {
    RecordKey::parse(&format!("{n:02x}").repeat(32)).unwrap()
}

fn job_id(n: u32) -> JobId {
    JobId::parse(&format!("20261105-010203-{n:08x}")).unwrap()
}

#[test]
fn one_job_per_key_across_processes_r88_t39() {
    let sb = Sandbox::new();
    let state = sb.root().join("state");
    let dirs = dirs_at(&state);
    let k = key(1);
    let first = job_id(1);
    let mut kids = Kids(Vec::new());
    let owner = kids.spawn(
        "claim",
        &[
            ("STATE", state.to_str().unwrap()),
            ("KEY", k.as_str()),
            ("JOB", first.as_str()),
        ],
    );
    wait_until(Duration::from_secs(10), || {
        sched::running_job(&dirs, &k).unwrap() == Some(first.clone())
    });
    // A second hook on the same tree attaches to the running job.
    match sched::claim_job(&dirs, &k, &job_id(2)).unwrap() {
        Claim::Running(Some(j)) => assert_eq!(j, first),
        other => panic!("expected to attach, got {other:?}"),
    }
    // The owner dies (SIGKILL): the kernel releases the key.
    kids.kill(owner);
    assert_eq!(sched::running_job(&dirs, &k).unwrap(), None);
    let Claim::Owner(claim) = sched::claim_job(&dirs, &k, &job_id(3)).unwrap() else {
        panic!("key must be free after the owner died");
    };
    assert_eq!(claim.job(), &job_id(3));
    assert_eq!(
        sched::running_job(&dirs, &k).unwrap(),
        Some(job_id(3)),
        "the file names the new owner"
    );
}

#[test]
fn waiter_liveness_is_the_lock_r89() {
    let sb = Sandbox::new();
    let state = sb.root().join("state");
    let dirs = dirs_at(&state);
    let job = job_id(7);
    let job_dir = dirs.job_dir(&job);
    assert!(!sched::has_live_waiter(&job_dir).unwrap());
    // A waiter never makes the job dir: that appears whole (R82).
    assert!(sched::register_waiter(&job_dir).is_err());
    assert!(!job_dir.exists());
    std::fs::create_dir_all(&job_dir).unwrap();
    let mut kids = Kids(Vec::new());
    let w = kids.spawn(
        "wait",
        &[("STATE", state.to_str().unwrap()), ("JOB", job.as_str())],
    );
    wait_until(Duration::from_secs(10), || {
        sched::has_live_waiter(&job_dir).unwrap()
    });
    kids.kill(w);
    assert!(!sched::has_live_waiter(&job_dir).unwrap());
    let left: Vec<PathBuf> = std::fs::read_dir(job_dir.join("waiters"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(left.is_empty(), "dead waiter files are removed: {left:?}");
    // In-process registration is dropped with the guard.
    let guard = sched::register_waiter(&job_dir).unwrap();
    assert!(sched::has_live_waiter(&job_dir).unwrap());
    drop(guard);
    assert!(!sched::has_live_waiter(&job_dir).unwrap());
}

fn meta(id: JobId, k: RecordKey, tree: u8, tier: Tier, origin: &Origin, at_s: i64) -> JobMeta {
    JobMeta {
        id,
        key: k,
        tree: Oid::parse(&format!("{tree:02x}").repeat(20)).unwrap(),
        tier,
        origin: origin.clone(),
        priority: Priority::Hook,
        created: jiff::Timestamp::from_second(1_793_862_000 + at_s).unwrap(),
        state: JobState::Queued,
    }
}

#[test]
fn queued_jobs_without_waiters_are_superseded_by_newer_ones_r89_t39() {
    let sb = Sandbox::new();
    let dirs = dirs_at(&sb.root().join("state"));
    let store = JobStore::new(&dirs);
    let origin = Origin {
        worktree: "/r/wt".into(),
        refname: "refs/heads/feat".into(),
    };
    let other_origin = Origin {
        worktree: "/r/wt".into(),
        refname: "refs/heads/other".into(),
    };
    let old = meta(job_id(1), key(1), 1, Tier::Fast, &origin, 0);
    let new = meta(job_id(2), key(2), 2, Tier::Fast, &origin, 5);
    let unrelated = meta(job_id(3), key(3), 3, Tier::Fast, &other_origin, 1);
    for m in [&old, &new, &unrelated] {
        store.create(m).unwrap();
    }

    // A waiting hook keeps the old job alive.
    let waiter = sched::register_waiter(&dirs.job_dir(&old.id)).unwrap();
    assert!(!store.is_stale(&old.id).unwrap());
    drop(waiter);
    assert!(store.supersede_if_stale(&old.id).unwrap());
    assert_eq!(store.read(&old.id).unwrap().state, JobState::Superseded);
    // The newest job and other origins stay.
    assert!(!store.supersede_if_stale(&new.id).unwrap());
    assert!(!store.supersede_if_stale(&unrelated.id).unwrap());

    // A started job runs to completion.
    let running = JobState::Running {
        started: jiff::Timestamp::now(),
        pid: 1,
    };
    let t = store
        .transition(&unrelated.id, &[StateKind::Queued], running.clone())
        .unwrap();
    assert!(matches!(t, Transition::Done(_)));
    let newer_same = meta(job_id(4), key(4), 4, Tier::Fast, &other_origin, 9);
    store.create(&newer_same).unwrap();
    assert!(!store.supersede_if_stale(&unrelated.id).unwrap());

    // A full pre-warm of the same tree is not stale next to a newer fast job.
    let origin3 = Origin {
        worktree: "/r/wt3".into(),
        refname: "refs/heads/x".into(),
    };
    let full = meta(job_id(5), key(5), 7, Tier::Full, &origin3, 0);
    let fast_same_tree = meta(job_id(6), key(6), 7, Tier::Fast, &origin3, 3);
    store.create(&full).unwrap();
    store.create(&fast_same_tree).unwrap();
    assert!(!store.is_stale(&full.id).unwrap());
    assert!(!store.is_stale(&fast_same_tree.id).unwrap());
}

#[test]
fn transitions_are_guarded_and_atomic() {
    let sb = Sandbox::new();
    let dirs = dirs_at(&sb.root().join("state"));
    let store = JobStore::new(&dirs);
    let origin = Origin {
        worktree: "/r".into(),
        refname: "HEAD".into(),
    };
    let m = meta(job_id(9), key(9), 9, Tier::Full, &origin, 0);
    store.create(&m).unwrap();
    // Eight threads race to start the job: exactly one wins.
    let wins: usize = std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let store = &store;
                let id = &m.id;
                s.spawn(move || {
                    matches!(
                        store
                            .transition(
                                id,
                                &[StateKind::Queued],
                                JobState::Running {
                                    started: jiff::Timestamp::now(),
                                    pid: i,
                                },
                            )
                            .unwrap(),
                        Transition::Done(_)
                    )
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| usize::from(h.join().unwrap()))
            .sum()
    });
    assert_eq!(wins, 1);
    let done = store
        .transition(
            &m.id,
            &[StateKind::Running],
            JobState::Finished {
                verdict: Verdict::Pass,
            },
        )
        .unwrap();
    assert!(matches!(done, Transition::Done(_)));
    let json = std::fs::read_to_string(dirs.job_dir(&m.id).join("job.json")).unwrap();
    assert!(
        json.contains("\"state\": \"finished\"") && json.contains("\"verdict\": \"pass\""),
        "{json}"
    );
    assert_eq!(store.list().unwrap().len(), 1);
}

#[test]
fn cancel_ends_queued_jobs_and_flags_running_ones_r89_t39() {
    let sb = Sandbox::new();
    let dirs = dirs_at(&sb.root().join("state"));
    let store = JobStore::new(&dirs);
    let origin = Origin {
        worktree: "/r".into(),
        refname: "HEAD".into(),
    };
    let queued = meta(job_id(1), key(1), 1, Tier::Fast, &origin, 0);
    let running = meta(job_id(2), key(2), 2, Tier::Fast, &origin, 1);
    store.create(&queued).unwrap();
    store.create(&running).unwrap();
    store
        .transition(
            &running.id,
            &[StateKind::Queued],
            JobState::Running {
                started: jiff::Timestamp::now(),
                pid: 1,
            },
        )
        .unwrap();

    assert_eq!(
        store.request_cancel(&queued.id).unwrap(),
        CancelOutcome::Cancelled
    );
    assert_eq!(store.read(&queued.id).unwrap().state, JobState::Cancelled);
    assert!(!store.cancel_requested(&running.id));
    assert_eq!(
        store.request_cancel(&running.id).unwrap(),
        CancelOutcome::Requested
    );
    assert!(store.cancel_requested(&running.id));
    assert_eq!(
        store.request_cancel(&queued.id).unwrap(),
        CancelOutcome::AlreadyEnded(JobState::Cancelled)
    );
    // A cancelled job leaves the origin queue.
    let qdir = dirs.job_queue_dir().join(origin.hash());
    let names: Vec<String> = std::fs::read_dir(&qdir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert!(names.is_empty(), "{names:?}");
}

#[test]
fn a_held_key_of_an_ended_job_is_not_a_running_job_r88() {
    let sb = Sandbox::new();
    let state = sb.root().join("state");
    let dirs = dirs_at(&state);
    let store = JobStore::new(&dirs);
    let k = key(3);
    let ended = job_id(30);
    let origin = Origin {
        worktree: "/r/wt".into(),
        refname: "refs/heads/feat".into(),
    };
    let mut m = meta(ended.clone(), k.clone(), 3, Tier::Fast, &origin, 0);
    m.state = JobState::Finished {
        verdict: Verdict::Pass,
    };
    store.create(&m).unwrap();
    // The ended job's id is still in the key file, and someone holds the
    // lock for a moment (a waiter probing it, or the runner on its way
    // out): the claim waits for it instead of attaching to the old job.
    let Claim::Owner(c) = sched::claim_job(&dirs, &k, &ended).unwrap() else {
        panic!("free key");
    };
    let holder = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        drop(c);
    });
    let got = sched::claim_job(&dirs, &k, &job_id(31)).unwrap();
    holder.join().unwrap();
    match got {
        Claim::Owner(c) => assert_eq!(c.job(), &job_id(31)),
        other => panic!("attached to an ended job: {other:?}"),
    }
}
