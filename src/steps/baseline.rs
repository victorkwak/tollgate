//! Python baselines (R94): the `pyright-baseline` and `pytest-baseline`
//! step kinds and `tollgate baseline record`, reimplemented from
//! `~/.claude/hooks/pyright-baseline.sh` and `pytest-baseline.sh` with the
//! same files, fingerprints and rules, so baselines those scripts recorded
//! keep their meaning.
//!
//! pyright: `pyright --outputjson --level error`. Each error is
//! fingerprinted as `path|rule|message`: the path relative to the root, the
//! rule or `-`, and the message with every run of whitespace collapsed to
//! one space (jq's `\s`, which is Unicode `White_Space`, the same set as
//! [`char::is_whitespace`]). No line numbers: they shift on every edit.
//! With no baseline any error fails; with one, only fingerprints whose
//! count grew fail.
//!
//! pytest: `pytest --tb=no -q --color=no -o cache_dir=<tmp>`; the failing
//! node ids come from the run's own `lastfailed` cache (node ids of
//! parametrized tests can hold spaces and ` - `, so the summary cannot be
//! split). Exit 2, 3 and 4 (the run did not complete) are never diffed. Exit
//! 5 (nothing collected) passes, except with a baseline that expects
//! failures. New failures are re-run in isolation (at most
//! [`RERUN_CAP`]) to label them, and fail either way.
//!
//! In jobs the tools run with `uv run --no-sync` after the setup `uv sync
//! --frozen` (R45, R46) and the baseline comes from the policy commit
//! (R49, L2), written into the job dir by the runner. One rule is stricter
//! than the script: a pytest run that fails with no `lastfailed` cache (a
//! plugin or `addopts` turned the cache provider off) fails, because its
//! failures cannot be compared with a baseline.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

/// The pyright baseline file (R71, R94).
pub const PYRIGHT_FILE: &str = ".pyright-baseline.json";
/// The pytest baseline file (R71, R94).
pub const PYTEST_FILE: &str = ".pytest-baseline.json";
/// New failures above this count are not re-run: that many at once is one
/// breakage, not flake.
pub const RERUN_CAP: usize = 25;
/// Lines listed per report.
pub const LIST_CAP: usize = 25;

/// Which baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `pyright-baseline`.
    Pyright,
    /// `pytest-baseline`.
    Pytest,
}

impl Kind {
    /// The baseline file name.
    #[must_use]
    pub fn file(self) -> &'static str {
        match self {
            Self::Pyright => PYRIGHT_FILE,
            Self::Pytest => PYTEST_FILE,
        }
    }

    /// The tool name.
    #[must_use]
    pub fn tool(self) -> &'static str {
        match self {
            Self::Pyright => "pyright",
            Self::Pytest => "pytest",
        }
    }
}

/// What a baseline step found, for the report (R91). The step writes it
/// to the path the runner passes with `--findings`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Findings {
    /// One-line summary of a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// New diagnostics or failing node ids (at most [`LIST_CAP`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<String>,
    /// Commands that re-run what failed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rerun: Vec<String>,
    /// Notes on a pass (fixed baseline entries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// The verdict of a baseline comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// True when the step passes.
    pub pass: bool,
    /// The text for the step log (the script's stderr).
    pub text: String,
    /// For the report.
    pub findings: Findings,
}

/// Collapses every run of whitespace to one space, as jq's
/// `gsub("\\s+"; " ")` does.
#[must_use]
pub fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    out
}

/// Quotes `s` for `sh` when it needs it.
#[must_use]
pub fn sh_quote(s: &str) -> String {
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"/._-:=+,@".contains(&b))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

/// `cd <root> && ` for a root other than the repo root.
fn cd(root: &str) -> String {
    if root.is_empty() || root == "." {
        String::new()
    } else {
        format!("cd {} && ", sh_quote(root))
    }
}

/// The record hint: baselines are recorded at an interactive terminal.
fn record_hint(kind: Kind, root: &str) -> String {
    let cmd = format!("tollgate baseline record {}", kind.tool());
    let inner = if root.is_empty() || root == "." {
        cmd
    } else {
        format!("(cd {} && {cmd})", sh_quote(root))
    };
    format!(
        "\nIf these predate your change, a baseline can be recorded at an interactive\nterminal (TTY only, R94); it applies once it merges to a full ref (L2):\n\n  git stash -u && {inner} && git stash pop\n"
    )
}

/// One pyright run: errors by fingerprint, in first-seen order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyrightRun {
    /// pyright's version.
    pub version: String,
    /// Fingerprint -> count, in first-seen order.
    pub counts: Vec<(String, u64)>,
    /// `path:line  rule  message` per error, in output order.
    pub lines: Vec<String>,
}

impl PyrightRun {
    /// Total error count.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.counts.iter().map(|(_, n)| n).sum()
    }

    fn count_map(&self) -> BTreeMap<String, u64> {
        self.counts.iter().cloned().collect()
    }
}

/// Parses `pyright --outputjson` output. `roots` are the forms of the dir
/// pyright ran in (as given and canonical); paths under one are made
/// relative to it, so a baseline holds across checkouts and worktrees.
pub fn parse_pyright(json: &str, roots: &[&Path]) -> Result<PyrightRun, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| format!("not JSON: {e}"))?;
    let diags = v
        .get("generalDiagnostics")
        .and_then(serde_json::Value::as_array)
        .ok_or("no generalDiagnostics in the output")?;
    let mut counts: Vec<(String, u64)> = Vec::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    let mut lines = Vec::new();
    for d in diags {
        if d["severity"] != "error" {
            continue;
        }
        let file = d["file"].as_str().unwrap_or_default();
        let rel = roots
            .iter()
            .find_map(|r| {
                let prefix = format!("{}/", r.display());
                file.strip_prefix(&prefix).map(str::to_owned)
            })
            .unwrap_or_else(|| file.to_owned());
        let rule = match &d["rule"] {
            serde_json::Value::Null | serde_json::Value::Bool(false) => "-".to_owned(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        let message = collapse_ws(d["message"].as_str().unwrap_or_default());
        let key = format!("{rel}|{rule}|{message}");
        match index.get(&key) {
            Some(i) => counts[*i].1 += 1,
            None => {
                index.insert(key.clone(), counts.len());
                counts.push((key, 1));
            }
        }
        let line = d["range"]["start"]["line"].as_u64().unwrap_or(0) + 1;
        lines.push(format!("{rel}:{line}  {rule}  {message}"));
    }
    Ok(PyrightRun {
        version: v["version"].as_str().unwrap_or_default().to_owned(),
        counts,
        lines,
    })
}

/// `path|rule|message` as `path  rule  message` (rule and path hold no
/// `|`; messages can).
fn show_key(key: &str) -> String {
    let mut parts = key.splitn(3, '|');
    let (f, r, m) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    format!("{f}  {r}  {m}")
}

/// A JSON number as a count (jq's `// 0` for anything else).
fn count_of(v: &serde_json::Value) -> u64 {
    v.as_u64()
        .or_else(|| v.as_f64().filter(|f| *f >= 0.0).map(|f| f.floor() as u64))
        .unwrap_or(0)
}

fn parse_baseline(text: &str, kind: Kind) -> Result<serde_json::Value, String> {
    serde_json::from_str(text).map_err(|e| format!("baseline {} is not JSON: {e}", kind.file()))
}

/// Compares a pyright run with the baseline text (`None`: no baseline
/// file), as `pyright-baseline.sh` does.
pub fn judge_pyright(run: &PyrightRun, baseline: Option<&str>, root: &str) -> Judgement {
    let total = run.total();
    let rerun = vec![format!("{}uv run pyright", cd(root))];
    let Some(text) = baseline else {
        if total == 0 {
            return pass(Vec::new());
        }
        let summary = format!("{total} pyright error(s).");
        let items: Vec<String> = run.lines.iter().take(LIST_CAP).cloned().collect();
        let mut out = format!("{summary}\n\n");
        for l in &items {
            out.push_str(&format!("  {l}\n"));
        }
        out.push_str(&record_hint(Kind::Pyright, root));
        return fail(out, summary, items, rerun);
    };
    let base = match parse_baseline(text, Kind::Pyright) {
        Ok(b) => b,
        Err(e) => return fail(e.clone(), e, Vec::new(), Vec::new()),
    };
    let base_counts: BTreeMap<String, u64> = base["counts"]
        .as_object()
        .map(|m| m.iter().map(|(k, v)| (k.clone(), count_of(v))).collect())
        .unwrap_or_default();
    let base_total = count_of(&base["total"]);
    let added: Vec<(&str, u64)> = run
        .counts
        .iter()
        .filter_map(|(k, n)| {
            let b = base_counts.get(k).copied().unwrap_or(0);
            (*n > b).then(|| (k.as_str(), n - b))
        })
        .collect();
    let added_n: u64 = added.iter().map(|(_, n)| n).sum();
    if added_n != 0 {
        let summary = format!(
            "{added_n} new pyright error(s) not in the baseline (baseline {base_total}, now {total}):"
        );
        let items: Vec<String> = added
            .iter()
            .take(LIST_CAP)
            .map(|(k, _)| show_key(k))
            .collect();
        let mut out = format!("{summary}\n\n");
        for l in &items {
            out.push_str(&format!("  {l}\n"));
        }
        out.push_str(
            "\nThese are yours: the baseline holds every error that predates your work.\n",
        );
        return fail(out, summary, items, rerun);
    }
    let cur = run.count_map();
    let stale: u64 = base_counts
        .iter()
        .map(|(k, b)| b.saturating_sub(cur.get(k).copied().unwrap_or(0)))
        .sum();
    let mut notes = Vec::new();
    if stale != 0 {
        notes.push(format!(
            "{stale} baseline entry/entries are now fixed - refresh with `tollgate baseline record pyright` to lock the gains in."
        ));
    }
    pass(notes)
}

fn pass(notes: Vec<String>) -> Judgement {
    Judgement {
        pass: true,
        text: notes.iter().map(|n| format!("{n}\n")).collect(),
        findings: Findings {
            notes,
            ..Findings::default()
        },
    }
}

fn fail(text: String, summary: String, items: Vec<String>, rerun: Vec<String>) -> Judgement {
    Judgement {
        pass: false,
        text: if text.ends_with('\n') {
            text
        } else {
            format!("{text}\n")
        },
        findings: Findings {
            summary: Some(summary),
            items,
            rerun,
            notes: Vec::new(),
        },
    }
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

/// Node ids with a truthy value in a pytest `lastfailed` cache or a
/// baseline's `tests` map.
fn truthy_keys(v: &serde_json::Value) -> BTreeSet<String> {
    v.as_object()
        .map(|m| {
            m.iter()
                .filter(|(_, v)| {
                    !matches!(v, serde_json::Value::Null | serde_json::Value::Bool(false))
                })
                .map(|(k, _)| k.clone())
                .collect()
        })
        .unwrap_or_default()
}

/// The failing node ids of a pytest run with `-o cache_dir=<dir>`; `None`
/// when the run left no `lastfailed` file.
#[must_use]
pub fn failed_set(cache_dir: &Path) -> Option<BTreeSet<String>> {
    let text = std::fs::read_to_string(cache_dir.join("v/cache/lastfailed")).ok()?;
    Some(
        serde_json::from_str::<serde_json::Value>(&text)
            .map(|v| truthy_keys(&v))
            .unwrap_or_default(),
    )
}

/// One pytest run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PytestRun {
    /// Exit code; `None` when a signal ended it.
    pub rc: Option<i32>,
    /// stdout and stderr.
    pub output: String,
    /// Failing node ids; `None` when no `lastfailed` file was written.
    pub failed: Option<BTreeSet<String>>,
}

/// Compares a pytest run with the baseline text (`None`: no baseline
/// file), as `pytest-baseline.sh` does. `recheck` re-runs node ids in
/// isolation and returns the ones that failed again (`None` when that run
/// gave no answer).
pub fn judge_pytest(
    run: &PytestRun,
    baseline: Option<&str>,
    root: &str,
    recheck: &mut dyn FnMut(&[String]) -> Option<BTreeSet<String>>,
) -> Judgement {
    if !matches!(run.rc, Some(0 | 1 | 5)) {
        let rc = run
            .rc
            .map_or_else(|| "a signal".to_owned(), |c| c.to_string());
        let summary =
            format!("pytest could not complete the run (exit {rc}) - no baseline applies:");
        let out = format!("{summary}\n\n{}\n", tail(&run.output, 25));
        return fail(out, summary, Vec::new(), Vec::new());
    }
    let cur = run.failed.clone().unwrap_or_default();
    let total = cur.len();
    let rerun_of = |ids: &[&String]| {
        let quoted: Vec<String> = ids.iter().map(|i| sh_quote(i)).collect();
        vec![format!("{}uv run pytest {}", cd(root), quoted.join(" "))]
    };
    let Some(text) = baseline else {
        if matches!(run.rc, Some(0 | 5)) {
            return pass(Vec::new());
        }
        let summary = format!("{total} failing test(s).");
        let items: Vec<String> = cur.iter().take(LIST_CAP).cloned().collect();
        let mut out = format!("{summary}\n\n");
        for i in &items {
            out.push_str(&format!("  {i}\n"));
        }
        if run.failed.is_none() {
            out.push_str("\npytest wrote no lastfailed cache, so its failures have no node ids.\n");
        }
        out.push_str(&record_hint(Kind::Pytest, root));
        let ids: Vec<&String> = cur.iter().take(LIST_CAP).collect();
        let rerun = if ids.is_empty() {
            vec![format!("{}uv run pytest", cd(root))]
        } else {
            rerun_of(&ids)
        };
        return fail(out, summary, items, rerun);
    };
    let base = match parse_baseline(text, Kind::Pytest) {
        Ok(b) => b,
        Err(e) => return fail(e.clone(), e, Vec::new(), Vec::new()),
    };
    let base_tests = truthy_keys(&base["tests"]);
    let base_total = count_of(&base["total"]);
    if run.rc == Some(5) && base_total > 0 {
        let summary = format!(
            "pytest collected no tests at all, but the baseline expects {base_total} failure(s)."
        );
        let out = format!(
            "{summary}\nThe suite stopped running - that is a break, not progress:\n\n{}\n",
            tail(&run.output, 15)
        );
        return fail(out, summary, Vec::new(), Vec::new());
    }
    if run.rc == Some(1) && run.failed.is_none() {
        let summary = "pytest failed but wrote no lastfailed cache (a plugin or addopts turned the cache provider off?): its failures cannot be compared with the baseline.".to_owned();
        let out = format!("{summary}\n\n{}\n", tail(&run.output, 25));
        return fail(
            out,
            summary,
            Vec::new(),
            vec![format!("{}uv run pytest", cd(root))],
        );
    }
    let added: Vec<String> = cur
        .iter()
        .filter(|t| !base_tests.contains(*t))
        .cloned()
        .collect();
    if !added.is_empty() {
        let verdict = (added.len() <= RERUN_CAP)
            .then(|| recheck(&added))
            .flatten();
        let summary = format!(
            "{} new failing test(s) not in the baseline (baseline {base_total}, now {total}):",
            added.len()
        );
        let items: Vec<String> = added
            .iter()
            .take(LIST_CAP)
            .map(|t| match &verdict {
                None => t.clone(),
                Some(v) if v.contains(t) => format!("{t}  [reproduced in isolation]"),
                Some(_) => format!("{t}  [passed in isolation - flaky or order-dependent]"),
            })
            .collect();
        let mut out = format!("{summary}\n\n");
        for i in &items {
            out.push_str(&format!("  {i}\n"));
        }
        if verdict.is_none() && added.len() > RERUN_CAP {
            out.push_str(&format!(
                "\n{n} new failures is past the re-run cap, so none were rechecked.\nThat many at once is usually one root cause, not {n}.\n",
                n = added.len()
            ));
        } else {
            out.push_str("\nReproduced ones are yours. Ones that passed in isolation failed only in the\nfull run - either flake or a test-ordering dependency; rerun the suite to\nconfirm before assuming your change is at fault.\n");
        }
        let ids: Vec<&String> = added.iter().take(LIST_CAP).collect();
        return fail(out, summary, items, rerun_of(&ids));
    }
    let fixed = base_tests.iter().filter(|t| !cur.contains(*t)).count();
    let mut notes = Vec::new();
    if fixed != 0 {
        notes.push(format!(
            "{fixed} baselined failure(s) now pass - refresh with `tollgate baseline record pytest` to lock the gains in."
        ));
    }
    pass(notes)
}

/// How the tools run: `uv run --no-sync` in jobs (after `uv sync
/// --frozen`, R46), `uv run` when recording at a terminal (as the scripts
/// did).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sync {
    /// `uv run --no-sync`.
    No,
    /// `uv run`.
    Yes,
}

fn uv(sync: Sync, cwd: &Path) -> Command {
    let mut c = Command::new("uv");
    c.current_dir(cwd).stdin(Stdio::null()).arg("run");
    if sync == Sync::No {
        c.arg("--no-sync");
    }
    c
}

/// Runs pyright in `cwd`; `Err` with the output when it gave no JSON.
pub fn run_pyright(sync: Sync, cwd: &Path) -> Result<PyrightRun, String> {
    let out = uv(sync, cwd)
        .args(["pyright", "--outputjson", "--level", "error"])
        .output()
        .map_err(|e| format!("pyright did not return JSON - it failed to run:\nuv: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let canonical = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_owned());
    parse_pyright(&stdout, &[cwd, &canonical]).map_err(|_| {
        format!(
            "pyright did not return JSON - it failed to run:\n{}\n{}",
            tail(&stderr, 20),
            tail(&stdout, 20)
        )
    })
}

/// Runs pytest in `cwd` with its cache in `cache_dir`; `ids` limits the run
/// to those node ids.
pub fn run_pytest(sync: Sync, cwd: &Path, cache_dir: &Path, ids: &[String]) -> PytestRun {
    let mut cmd = uv(sync, cwd);
    cmd.args(["pytest", "--tb=no", "-q", "--color=no", "-o"])
        .arg(format!("cache_dir={}", cache_dir.display()));
    if !ids.is_empty() {
        cmd.arg("--").args(ids);
    }
    match cmd.output() {
        Ok(out) => PytestRun {
            rc: out.status.code(),
            output: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
            failed: failed_set(cache_dir),
        },
        Err(e) => PytestRun {
            rc: Some(2),
            output: format!("uv: {e}"),
            failed: None,
        },
    }
}

/// A scratch dir for pytest caches, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let p =
            std::env::temp_dir().join(format!("tollgate-pytest-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p)?;
        Ok(Self(p))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `tollgate __step pyright-baseline|pytest-baseline`: runs the tool in the
/// current dir (the step's root) with `uv run --no-sync`, compares with
/// `baseline` (the policy commit's file, R49), prints the result, writes
/// `findings` and returns the exit code (0 pass, 1 fail).
pub fn step(kind: Kind, baseline: Option<&Path>, findings: &Path, root: &str) -> u8 {
    let cwd = match std::env::current_dir() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("tollgate __step: cannot read the current dir: {e}");
            return 2;
        }
    };
    let base_text = match baseline.map(std::fs::read_to_string).transpose() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("tollgate __step: baseline: {e}");
            return 2;
        }
    };
    let judgement = match kind {
        Kind::Pyright => match run_pyright(Sync::No, &cwd) {
            Ok(run) => judge_pyright(&run, base_text.as_deref(), root),
            Err(text) => {
                let summary = text.lines().next().unwrap_or_default().to_owned();
                fail(text, summary, Vec::new(), Vec::new())
            }
        },
        Kind::Pytest => {
            let scratch = match Scratch::new() {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("tollgate __step: temp dir: {e}");
                    return 2;
                }
            };
            let run = run_pytest(Sync::No, &cwd, &scratch.0.join("cache"), &[]);
            print!("{}", run.output);
            let mut recheck = |ids: &[String]| {
                eprintln!("re-running {} new failure(s) in isolation", ids.len());
                let again = run_pytest(Sync::No, &cwd, &scratch.0.join("recheck"), ids);
                print!("{}", again.output);
                again.failed
            };
            judge_pytest(&run, base_text.as_deref(), root, &mut recheck)
        }
    };
    eprint!("{}", judgement.text);
    if let Ok(json) = serde_json::to_vec_pretty(&judgement.findings) {
        let _ = crate::fsx::write_atomic(findings, &json);
    }
    u8::from(!judgement.pass)
}

/// The text of a baseline file for `run`, in the scripts' format.
#[must_use]
pub fn pyright_baseline_json(run: &PyrightRun, generated: &str, commit: &str) -> String {
    let counts: serde_json::Map<String, serde_json::Value> = run
        .counts
        .iter()
        .map(|(k, n)| (k.clone(), serde_json::Value::from(*n)))
        .collect();
    let v = serde_json::json!({
        "version": 1,
        "generated": generated,
        "pyright": run.version,
        "commit": commit,
        "total": run.total(),
        "counts": counts,
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap_or_default())
}

/// The text of a pytest baseline file, in the script's format.
#[must_use]
pub fn pytest_baseline_json(failed: &BTreeSet<String>, generated: &str, commit: &str) -> String {
    let tests: serde_json::Map<String, serde_json::Value> = failed
        .iter()
        .map(|t| (t.clone(), serde_json::Value::Bool(true)))
        .collect();
    let v = serde_json::json!({
        "version": 1,
        "generated": generated,
        "commit": commit,
        "total": failed.len(),
        "tests": tests,
    });
    format!("{}\n", serde_json::to_string_pretty(&v).unwrap_or_default())
}

/// `date -Iseconds`.
#[must_use]
pub fn now_iso() -> String {
    jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string()
}

/// Records a baseline in `root` (the dir with `pyproject.toml`), with `uv
/// run` as the scripts did. `commit` is `git rev-parse --short HEAD` or
/// `unknown`. Returns the message to print.
pub fn record(kind: Kind, root: &Path, commit: &str) -> Result<String, String> {
    let path = root.join(kind.file());
    let (text, total) = match kind {
        Kind::Pyright => {
            let run = run_pyright(Sync::Yes, root)?;
            (pyright_baseline_json(&run, &now_iso(), commit), run.total())
        }
        Kind::Pytest => {
            let scratch = Scratch::new().map_err(|e| format!("temp dir: {e}"))?;
            let run = run_pytest(Sync::Yes, root, &scratch.0.join("cache"), &[]);
            if !matches!(run.rc, Some(0 | 1 | 5)) {
                return Err(format!(
                    "pytest could not complete the run (exit {}) - no baseline recorded:\n\n{}",
                    run.rc
                        .map_or_else(|| "a signal".to_owned(), |c| c.to_string()),
                    tail(&run.output, 25)
                ));
            }
            if run.rc == Some(1) && run.failed.is_none() {
                return Err(
                    "pytest failed but wrote no lastfailed cache: no baseline recorded".into(),
                );
            }
            let failed = run.failed.unwrap_or_default();
            let n = failed.len() as u64;
            (pytest_baseline_json(&failed, &now_iso(), commit), n)
        }
    };
    crate::fsx::write_atomic(&path, text.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    let what = match kind {
        Kind::Pyright => "pyright error(s)",
        Kind::Pytest => "test failure(s)",
    };
    Ok(format!(
        "Recorded {total} pre-existing {what} to {}\nCommit it so the gate means the same thing for everyone; it applies once it merges to a full ref (L2).",
        path.display()
    ))
}

/// The nearest dir from `cwd` up to `top` that holds `pyproject.toml`.
fn python_root(cwd: &Path, top: &Path) -> Option<PathBuf> {
    cwd.ancestors()
        .take_while(|a| a.starts_with(top))
        .find(|a| a.join("pyproject.toml").is_file())
        .map(Path::to_owned)
}

/// `tollgate baseline record pyright|pytest [--force]` (R94): at an
/// interactive terminal only (stdin and stdout are TTYs; Claude's Bash has
/// none), on a clean tree unless `--force`, in the nearest dir with
/// `pyproject.toml`. Returns the exit code.
pub fn record_cmd(env: &crate::env::EnvSnapshot, cwd: &Path, kind: Kind, force: bool) -> u8 {
    use std::io::IsTerminal as _;
    let tool = kind.tool();
    if !(std::io::stdin().is_terminal() && std::io::stdout().is_terminal()) {
        eprintln!(
            "tollgate baseline record: needs an interactive terminal on stdin and stdout (R94); a baseline is recorded by a person, not by an agent"
        );
        return crate::exit::FAIL;
    }
    let git = crate::gitx::Git::scrubbed(env, cwd);
    let top = match crate::gitx::RepoLayout::discover(&git) {
        Ok(l) => match l.worktree {
            Some(w) => w,
            None => {
                eprintln!("tollgate baseline record: bare repository: no work tree");
                return crate::exit::BLOCK;
            }
        },
        Err(e) => {
            eprintln!("tollgate baseline record: not in a git repository: {e}");
            return crate::exit::BLOCK;
        }
    };
    let cwd = std::fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_owned());
    let top = std::fs::canonicalize(&top).unwrap_or(top);
    let Some(root) = python_root(&cwd, &top) else {
        eprintln!(
            "tollgate baseline record: no pyproject.toml in {} or a parent inside the repo",
            cwd.display()
        );
        return crate::exit::BLOCK;
    };
    let git = git.in_dir(&root);
    if !force {
        let status = git.run([
            "status",
            "--porcelain",
            "--",
            ".",
            ":(exclude).pytest-baseline.json",
            ":(exclude).pyright-baseline.json",
        ]);
        let dirty = match status {
            Ok(out) => !out.trim_ascii().is_empty(),
            Err(e) => {
                eprintln!("tollgate baseline record: git status: {e}");
                return crate::exit::BLOCK;
            }
        };
        if dirty {
            let what = match kind {
                Kind::Pyright => "errors",
                Kind::Pytest => "failures",
            };
            eprintln!(
                "tollgate baseline record: the working tree is dirty.\nRecording now would bake your in-progress {what} into the baseline, which\nis the one thing a baseline must never contain. Stash first:\n\n  git stash -u && tollgate baseline record {tool} && git stash pop\n\nOr pass --force if the current state really is the intended baseline."
            );
            return crate::exit::FAIL;
        }
    }
    let commit = git
        .run_line(["rev-parse", "--short", "HEAD"])
        .unwrap_or_else(|_| "unknown".to_owned());
    match record(kind, &root, &commit) {
        Ok(msg) => {
            println!("{msg}");
            crate::exit::OK
        }
        Err(e) => {
            eprintln!("tollgate baseline record: {e}");
            crate::exit::FAIL
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `pyright --outputjson --level error` output (pyright 1.1.412)
    /// for a two-file project at /w/p, plus a warning and a repeat.
    const PYRIGHT_JSON: &str = r#"{
  "version": "1.1.412",
  "time": "1793872501451",
  "generalDiagnostics": [
    {"file": "/w/p/m.py", "severity": "error",
     "message": "Type \"int\" is not assignable to return type \"str\"\n  \"int\" is not assignable to \"str\"",
     "range": {"start": {"line": 1, "character": 11}, "end": {"line": 1, "character": 12}},
     "rule": "reportReturnType"},
    {"file": "/w/p/m.py", "severity": "warning", "message": "w",
     "range": {"start": {"line": 2, "character": 0}, "end": {"line": 2, "character": 1}}},
    {"file": "/w/p/tests/test_a.py", "severity": "error",
     "message": "Import \"pytest\" could not be resolved",
     "range": {"start": {"line": 0, "character": 7}, "end": {"line": 0, "character": 13}},
     "rule": "reportMissingImports"},
    {"file": "/w/p/m.py", "severity": "error",
     "message": "Type \"int\" is not assignable to return type \"str\"\n  \"int\" is not assignable to \"str\"",
     "range": {"start": {"line": 9, "character": 11}, "end": {"line": 9, "character": 12}},
     "rule": "reportReturnType"},
    {"file": "/elsewhere/x.py", "severity": "error", "message": "no rule",
     "range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}}
  ],
  "summary": {"filesAnalyzed": 2, "errorCount": 4}
}"#;

    const RETURN_KEY: &str = "m.py|reportReturnType|Type \"int\" is not assignable to return type \"str\" \"int\" is not assignable to \"str\"";

    fn run() -> PyrightRun {
        parse_pyright(PYRIGHT_JSON, &[Path::new("/w/p")]).unwrap()
    }

    #[test]
    fn whitespace_collapses_like_jq_r94() {
        // jq-1.8.2: `gsub("\\s+"; " ")` on these code points (checked).
        assert_eq!(collapse_ws("a\n\u{a0}\u{a0}b\tc\u{2003}d"), "a b c d");
        assert_eq!(collapse_ws("a\u{200b}b"), "a\u{200b}b", "ZWSP is no space");
        assert_eq!(collapse_ws("a\u{1c}b"), "a\u{1c}b");
        assert_eq!(collapse_ws("  x  "), " x ", "runs collapse, no trim");
    }

    #[test]
    fn pyright_fingerprints_are_path_rule_message_r94_t42() {
        let r = run();
        assert_eq!(r.version, "1.1.412");
        assert_eq!(
            r.counts,
            vec![
                (RETURN_KEY.to_owned(), 2),
                (
                    "tests/test_a.py|reportMissingImports|Import \"pytest\" could not be resolved"
                        .to_owned(),
                    1
                ),
                ("/elsewhere/x.py|-|no rule".to_owned(), 1),
            ],
            "NBSP and spaces collapse alike; warnings do not count; no line numbers"
        );
        assert_eq!(r.total(), 4);
        assert_eq!(
            r.lines[0],
            "m.py:2  reportReturnType  Type \"int\" is not assignable to return type \"str\" \"int\" is not assignable to \"str\""
        );
        assert!(parse_pyright("{}", &[]).is_err());
        assert!(parse_pyright("crash", &[]).is_err());
    }

    #[test]
    fn pyright_without_baseline_fails_on_any_error_r94() {
        let j = judge_pyright(&run(), None, "py");
        assert!(!j.pass);
        assert!(
            j.text
                .starts_with("4 pyright error(s).\n\n  m.py:2  reportReturnType")
        );
        assert!(
            j.text
                .contains("(cd py && tollgate baseline record pyright)")
        );
        assert_eq!(j.findings.items.len(), 4);
        assert_eq!(j.findings.rerun, ["cd py && uv run pyright"]);
        let clean = PyrightRun {
            version: "1".into(),
            counts: Vec::new(),
            lines: Vec::new(),
        };
        assert!(judge_pyright(&clean, None, ".").pass);
    }

    #[test]
    fn pyright_baseline_blocks_only_growth_r94_t42() {
        let r = run();
        let base = pyright_baseline_json(&r, "2026-11-05T00:00:00+00:00", "abc1234");
        let v: serde_json::Value = serde_json::from_str(&base).unwrap();
        assert_eq!(v["total"], 4);
        assert_eq!(v["counts"][RETURN_KEY], 2);
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            [
                "version",
                "generated",
                "pyright",
                "commit",
                "total",
                "counts"
            ],
            "the script's key order"
        );
        assert!(judge_pyright(&r, Some(&base), ".").pass);
        // One more of a known error: blocked, listed once.
        let mut more = r.clone();
        more.counts[0].1 = 3;
        let j = judge_pyright(&more, Some(&base), ".");
        assert!(!j.pass);
        assert!(
            j.text
                .starts_with("1 new pyright error(s) not in the baseline (baseline 4, now 5):"),
            "{}",
            j.text
        );
        assert_eq!(
            j.findings.items,
            [
                "m.py  reportReturnType  Type \"int\" is not assignable to return type \"str\" \"int\" is not assignable to \"str\""
            ]
        );
        // Fewer errors: pass with a refresh note.
        let mut fewer = r.clone();
        fewer.counts.remove(1);
        let j = judge_pyright(&fewer, Some(&base), ".");
        assert!(j.pass);
        assert_eq!(
            j.findings.notes,
            [
                "1 baseline entry/entries are now fixed - refresh with `tollgate baseline record pyright` to lock the gains in."
            ]
        );
        // A script-written baseline (jq layout, other key order) reads the same.
        let script = format!("{{\"counts\": {{{RETURN_KEY:?}: 2}}, \"total\": 2, \"version\": 1}}");
        let only_return = PyrightRun {
            counts: vec![(RETURN_KEY.to_owned(), 2)],
            ..r.clone()
        };
        assert!(judge_pyright(&only_return, Some(&script), ".").pass);
        // A broken baseline fails closed.
        assert!(!judge_pyright(&r, Some("{"), ".").pass);
    }

    fn pytest(rc: i32, failed: Option<&[&str]>) -> PytestRun {
        PytestRun {
            rc: Some(rc),
            output: "line\n".repeat(40),
            failed: failed.map(|f| f.iter().map(|s| (*s).to_owned()).collect()),
        }
    }

    fn never(_: &[String]) -> Option<BTreeSet<String>> {
        panic!("no re-run expected")
    }

    #[test]
    fn pytest_exit_codes_r94_t42() {
        for rc in [2, 3, 4] {
            let j = judge_pytest(&pytest(rc, Some(&["t::a"])), Some("{}"), ".", &mut never);
            assert!(!j.pass, "rc {rc} never passes");
            assert!(j.text.starts_with(&format!(
                "pytest could not complete the run (exit {rc}) - no baseline applies:"
            )));
            assert_eq!(j.text.lines().count(), 2 + 25, "tail of 25 lines");
        }
        assert!(judge_pytest(&pytest(5, None), None, ".", &mut never).pass);
        assert!(judge_pytest(&pytest(0, None), None, ".", &mut never).pass);
        let j = judge_pytest(
            &pytest(1, Some(&["t.py::b", "t.py::a"])),
            None,
            "py",
            &mut never,
        );
        assert!(!j.pass);
        assert!(
            j.text
                .starts_with("2 failing test(s).\n\n  t.py::a\n  t.py::b\n")
        );
        assert_eq!(j.findings.rerun, ["cd py && uv run pytest t.py::a t.py::b"]);
        // rc 5 with a baseline that expects failures: the suite stopped.
        let base = pytest_baseline_json(&["t.py::a".to_owned()].into(), "g", "c");
        let j = judge_pytest(&pytest(5, None), Some(&base), ".", &mut never);
        assert!(!j.pass);
        assert!(
            j.text
                .contains("collected no tests at all, but the baseline expects 1")
        );
        let empty = pytest_baseline_json(&BTreeSet::new(), "g", "c");
        assert!(judge_pytest(&pytest(5, None), Some(&empty), ".", &mut never).pass);
    }

    #[test]
    fn pytest_baseline_blocks_new_failures_with_isolation_labels_r94_t42() {
        let base = pytest_baseline_json(
            &["t.py::old".to_owned(), "t.py::fixed".to_owned()].into(),
            "g",
            "c",
        );
        let v: serde_json::Value = serde_json::from_str(&base).unwrap();
        assert_eq!(
            v.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["version", "generated", "commit", "total", "tests"]
        );
        // Only baselined failures (one fixed): pass with a note.
        let j = judge_pytest(
            &pytest(1, Some(&["t.py::old"])),
            Some(&base),
            ".",
            &mut never,
        );
        assert!(j.pass);
        assert_eq!(
            j.findings.notes,
            [
                "1 baselined failure(s) now pass - refresh with `tollgate baseline record pytest` to lock the gains in."
            ]
        );
        // New failures: re-run in isolation, labelled, blocked either way.
        let mut asked = Vec::new();
        let mut recheck = |ids: &[String]| {
            asked = ids.to_vec();
            Some(["t.py::new[a - b]".to_owned()].into())
        };
        let j = judge_pytest(
            &pytest(1, Some(&["t.py::old", "t.py::new[a - b]", "t.py::order"])),
            Some(&base),
            "py",
            &mut recheck,
        );
        assert!(!j.pass);
        assert_eq!(asked, ["t.py::new[a - b]", "t.py::order"]);
        assert!(
            j.text
                .starts_with("2 new failing test(s) not in the baseline (baseline 2, now 3):")
        );
        assert_eq!(
            j.findings.items,
            [
                "t.py::new[a - b]  [reproduced in isolation]",
                "t.py::order  [passed in isolation - flaky or order-dependent]"
            ]
        );
        assert_eq!(
            j.findings.rerun,
            ["cd py && uv run pytest 't.py::new[a - b]' t.py::order"]
        );
        // Past the re-run cap: no re-run.
        let many: Vec<String> = (0..=RERUN_CAP).map(|i| format!("t.py::n{i}")).collect();
        let refs: Vec<&str> = many.iter().map(String::as_str).collect();
        let j = judge_pytest(&pytest(1, Some(&refs)), Some(&base), ".", &mut never);
        assert!(!j.pass);
        assert!(j.text.contains("past the re-run cap"));
        assert_eq!(j.findings.items.len(), LIST_CAP);
        // A failing run with no lastfailed cache cannot be compared: fail.
        let j = judge_pytest(&pytest(1, None), Some(&base), ".", &mut never);
        assert!(!j.pass);
        assert!(j.text.contains("no lastfailed cache"));
    }

    #[test]
    fn lastfailed_reads_truthy_entries() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(failed_set(tmp.path()), None);
        let lf = tmp.path().join("v/cache/lastfailed");
        std::fs::create_dir_all(lf.parent().unwrap()).unwrap();
        std::fs::write(&lf, r#"{"a::x": true, "a::y": false, "a::z": null}"#).unwrap();
        assert_eq!(failed_set(tmp.path()), Some(["a::x".to_owned()].into()));
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(sh_quote("tests/t.py::a"), "tests/t.py::a");
        assert_eq!(sh_quote("t.py::p[a - b]"), "'t.py::p[a - b]'");
        assert_eq!(sh_quote("it's"), "'it'\\''s'");
    }
}
