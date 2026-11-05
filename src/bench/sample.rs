//! Load samplers of `tollgate bench` (L20): CPU load while the commits
//! run, and the connections of a test Postgres through `psql`.
//!
//! Each sampler is a thread that takes a sample at once, then one per
//! interval, and a last one when told to stop.

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde::Serialize;

/// One CPU sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpuSample {
    /// Milliseconds since the samplers started.
    pub t_ms: u64,
    /// One-minute load average (`getloadavg`).
    pub load1: f64,
    /// Busy share of all CPUs since the previous sample, in percent
    /// (Linux `/proc/stat`; absent elsewhere and on the first sample).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy_pct: Option<f64>,
}

/// One Postgres sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PgSample {
    /// Milliseconds since the samplers started.
    pub t_ms: u64,
    /// Client connections other than the sampler's own.
    pub connections: u64,
}

/// What the Postgres sampler saw.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PgSamples {
    /// The samples that worked.
    pub samples: Vec<PgSample>,
    /// Samples that failed.
    pub errors: u32,
    /// The last failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// The query: client backends other than this one.
pub const PG_QUERY: &str = "select count(*) from pg_stat_activity where backend_type = 'client backend' and pid <> pg_backend_pid()";

/// How long one `psql` call may take.
const PSQL_LIMIT: Duration = Duration::from_secs(10);

/// Running samplers.
#[derive(Debug)]
pub struct Samplers {
    stop: Arc<AtomicBool>,
    cpu: JoinHandle<Vec<CpuSample>>,
    pg: Option<JoinHandle<PgSamples>>,
}

/// Where and how to ask Postgres.
#[derive(Debug, Clone)]
pub struct PgTarget {
    /// The `psql` program.
    pub psql: PathBuf,
    /// Connection URL (never printed: it may hold a password).
    pub url: String,
    /// Environment of `psql`.
    pub env: Vec<(OsString, OsString)>,
}

fn ms_since(t0: Instant) -> u64 {
    u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Sleeps until `next` or until `stop` is set.
fn pause(stop: &AtomicBool, next: Instant) {
    while !stop.load(Ordering::SeqCst) {
        let now = Instant::now();
        if now >= next {
            return;
        }
        std::thread::sleep((next - now).min(Duration::from_millis(10)));
    }
}

/// Runs `take` at once, every `interval`, and once more after `stop`.
fn every<T>(stop: &AtomicBool, interval: Duration, mut take: impl FnMut() -> T) -> Vec<T> {
    let mut out = Vec::new();
    loop {
        let next = Instant::now() + interval;
        out.push(take());
        if stop.load(Ordering::SeqCst) {
            return out;
        }
        pause(stop, next);
    }
}

impl Samplers {
    /// Starts the CPU sampler, and the Postgres sampler when `pg` is set.
    #[must_use]
    pub fn start(interval: Duration, pg: Option<PgTarget>) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let t0 = Instant::now();
        let s = Arc::clone(&stop);
        let cpu = std::thread::spawn(move || {
            let mut last = None;
            every(&s, interval, || {
                let now = cpu_times();
                let busy_pct = match (last, now) {
                    (Some((busy0, total0)), Some((busy1, total1))) if total1 > total0 => {
                        let busy = busy1.saturating_sub(busy0) as f64;
                        Some(round1(100.0 * busy / (total1 - total0) as f64))
                    }
                    _ => None,
                };
                last = now;
                CpuSample {
                    t_ms: ms_since(t0),
                    load1: load1().unwrap_or(0.0),
                    busy_pct,
                }
            })
        });
        let pg = pg.map(|target| {
            let s = Arc::clone(&stop);
            std::thread::spawn(move || {
                let mut out = PgSamples::default();
                let results = every(&s, interval, || (ms_since(t0), pg_count(&target)));
                for (t_ms, r) in results {
                    match r {
                        Ok(connections) => out.samples.push(PgSample { t_ms, connections }),
                        Err(e) => {
                            out.errors += 1;
                            out.last_error = Some(e);
                        }
                    }
                }
                out
            })
        });
        Self { stop, cpu, pg }
    }

    /// Stops the samplers and returns what they saw.
    #[must_use]
    pub fn finish(self) -> (Vec<CpuSample>, Option<PgSamples>) {
        self.stop.store(true, Ordering::SeqCst);
        let cpu = self.cpu.join().unwrap_or_default();
        let pg = self.pg.map(|h| h.join().unwrap_or_default());
        (cpu, pg)
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The one-minute load average.
fn load1() -> Option<f64> {
    let mut l = [0f64; 3];
    // SAFETY: getloadavg writes at most `nelem` (3) doubles into `l`.
    let n = unsafe { libc::getloadavg(l.as_mut_ptr(), 3) };
    (n >= 1).then(|| (l[0] * 100.0).round() / 100.0)
}

/// (busy, total) CPU time of all CPUs since boot, in clock ticks.
#[cfg(target_os = "linux")]
fn cpu_times() -> Option<(u64, u64)> {
    let text = std::fs::read_to_string("/proc/stat").ok()?;
    let line = text.lines().next()?.strip_prefix("cpu ")?;
    let v: Vec<u64> = line
        .split_whitespace()
        .filter_map(|x| x.parse().ok())
        .collect();
    if v.len() < 5 {
        return None;
    }
    // user nice system idle iowait irq softirq steal; guest time is
    // already counted in user and nice.
    let total: u64 = v.iter().take(8).sum();
    let idle = v[3] + v[4];
    Some((total.saturating_sub(idle), total))
}

/// No portable per-interval CPU share on macOS without Mach calls; the
/// load average stands for it (L13).
#[cfg(not(target_os = "linux"))]
fn cpu_times() -> Option<(u64, u64)> {
    None
}

/// Asks Postgres for its client connections once.
fn pg_count(t: &PgTarget) -> Result<u64, String> {
    let mut child = Command::new(&t.psql)
        .env_clear()
        .envs(t.env.iter().map(|(k, v)| (k, v)))
        .env("PGCONNECT_TIMEOUT", "5")
        .args(["-X", "-A", "-t", "-q", "-d", &t.url, "-c", PG_QUERY])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", t.psql.display()))?;
    let end = Instant::now() + PSQL_LIMIT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < end => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("psql gave no answer in {}s", PSQL_LIMIT.as_secs()));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "psql {}: {}",
            out.status,
            err.lines().next().unwrap_or("").trim()
        ));
    }
    stdout
        .trim()
        .parse()
        .map_err(|_| format!("psql printed {:?}, not a count", stdout.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samplers_take_a_first_and_a_last_sample_l20() {
        let s = Samplers::start(Duration::from_secs(3600), None);
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        let (cpu, pg) = s.finish();
        assert!(started.elapsed() < Duration::from_secs(5), "stop waits");
        assert_eq!(cpu.len(), 2, "{cpu:?}");
        assert!(cpu.iter().all(|c| c.load1 >= 0.0));
        assert_eq!(cpu[0].busy_pct, None, "no interval before the first");
        #[cfg(target_os = "linux")]
        assert!(cpu[1].busy_pct.is_some(), "{cpu:?}");
        assert!(pg.is_none());
    }

    #[test]
    fn a_missing_psql_is_a_counted_error_l20() {
        let s = Samplers::start(
            Duration::from_secs(3600),
            Some(PgTarget {
                psql: "/nonexistent/psql".into(),
                url: "postgres://x".into(),
                env: Vec::new(),
            }),
        );
        let (_, pg) = s.finish();
        let pg = pg.unwrap();
        assert!(pg.samples.is_empty());
        assert!(pg.errors >= 1);
        assert!(pg.last_error.unwrap().contains("cannot run"));
    }
}
