//! Python jobs end to end: real uv, ruff, pyright and pytest on a generated
//! project, with no network (R45, R46, R49, R60, R91, R94, T25, T42, L2).
//!
//! pytest and ruff wheels are rebuilt from uv's cache, pyright is the one
//! on PATH (see `support::tools`); a test skips with a `SKIP` line when one
//! is missing.

mod support;

use std::ops::Not;
use std::path::PathBuf;
use std::process::Command;

use support::{Sandbox, job_id, tools};
use tollgate::steps::baseline;

const POLICY: &str = r#"version = 1

[[setup]]
name = "uv sync"
run = "uv sync --frozen"
cwd = "py"
when = ["py/pyproject.toml", "py/uv.lock"]

[[step]]
name = "ruff"
kind = "ruff"
cwd = "py"

[[step]]
name = "pyright"
kind = "pyright-baseline"
cwd = "py"

[[step]]
name = "pytest"
kind = "pytest-baseline"
cwd = "py"
"#;

const APP: &str = "def add(a: int, b: int) -> int:\n    return a + b\n";
const LEGACY: &str = "count: int = \"many\"\n";
const TESTS: &str = "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n\n\ndef test_old():\n    assert add(1, 1) == 3\n";

struct Project {
    sb: Sandbox,
    repo: PathBuf,
    uv: PathBuf,
}

fn step<'a>(report: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    report["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["name"] == name)
        .unwrap_or_else(|| panic!("no step {name} in {report}"))
}

/// A repo with a uv project in `py/` whose only package index is a
/// `wheels` symlink to wheels rebuilt from uv's cache.
fn project(test: &str, policy: Option<&str>, clean: bool) -> Option<Project> {
    let Some(uv) = tools::which("uv") else {
        tools::skip(test, "uv is not on PATH");
        return None;
    };
    let Some(pyright) = tools::which("pyright") else {
        tools::skip(test, "pyright is not on PATH");
        return None;
    };
    let sb = Sandbox::new();
    let wheels = sb.root().join("wheels");
    let mut names = tools::PYTEST.to_vec();
    names.push("ruff");
    if tools::wheels(&names, &wheels).is_none() {
        tools::skip(
            test,
            "uv's cache has no wheels of pytest, its dependencies and ruff for this platform",
        );
        return None;
    }
    let repo = sb.root().join("app");
    let py = repo.join("py");
    std::fs::create_dir_all(py.join("tests")).unwrap();
    std::os::unix::fs::symlink(&wheels, py.join("wheels")).unwrap();
    if let Some(policy) = policy {
        std::fs::write(repo.join("tollgate.toml"), policy).unwrap();
    }
    let files: &[(&str, &str)] = &[
        (".gitignore", ".venv/\n__pycache__/\n"),
        ("py/app.py", APP),
        (
            "py/legacy.py",
            if clean { "count: int = 1\n" } else { LEGACY },
        ),
        (
            "py/tests/test_app.py",
            if clean {
                "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n"
            } else {
                TESTS
            },
        ),
    ];
    for (p, text) in files {
        std::fs::write(repo.join(p), text).unwrap();
    }
    let mut toml = tools::pyproject("py", &["pytest", "ruff"]);
    toml.push_str("\n[tool.pytest.ini_options]\npythonpath = [\".\"]\n");
    std::fs::write(py.join("pyproject.toml"), toml).unwrap();
    let env = sb.env();
    let offline = tools::offline_env(&sb.root());
    if Command::new(&uv)
        .arg("lock")
        .current_dir(&py)
        .env_clear()
        .envs(env.iter())
        .envs(offline.iter().map(|(k, v)| (k, v.as_os_str())))
        .output()
        .is_ok_and(|o| o.status.success())
        .not()
    {
        tools::skip(test, "uv lock cannot resolve from the rebuilt wheels");
        return None;
    }
    sb.git(&repo, &["init", "-q"]);
    sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n{}",
        tools::job_config(&[&uv, &pyright])
    ));
    Some(Project { sb, repo, uv })
}

impl Project {
    fn py(&self) -> PathBuf {
        self.repo.join("py")
    }

    fn write(&self, path: &str, text: &str) {
        let p = self.repo.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, text).unwrap();
        self.sb.git(&self.repo, &["add", path]);
    }

    fn commit(&self, msg: &str) {
        self.sb.git(&self.repo, &["add", "-A"]);
        self.sb
            .git(&self.repo, &["commit", "-q", "--no-verify", "-m", msg]);
    }

    fn check(&self, args: &[&str]) -> (Option<i32>, String, serde_json::Value) {
        let r = self.sb.tollgate(&self.repo, args);
        let job = job_id(&r.out);
        (r.code, r.out, self.sb.report(&job))
    }

    /// The baseline the scripts would record now: real pyright in the
    /// agent's `.venv` (made by `uv sync` here), through the library's own
    /// fingerprinting.
    fn pyright_baseline(&self) -> String {
        let env = self.sb.env();
        let offline = tools::offline_env(&self.sb.root());
        tools::run(
            &self.uv,
            &["sync", "--frozen", "-q"],
            &self.py(),
            &env,
            &offline,
        );
        let out = Command::new(&self.uv)
            .args([
                "run",
                "--no-sync",
                "pyright",
                "--outputjson",
                "--level",
                "error",
            ])
            .current_dir(self.py())
            .env_clear()
            .envs(env.iter())
            .envs(offline.iter().map(|(k, v)| (k, v.as_os_str())))
            .output()
            .unwrap();
        let py = self.py();
        let run = baseline::parse_pyright(&String::from_utf8_lossy(&out.stdout), &[&py])
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr)));
        assert_eq!(run.total(), 1, "{:?}", run.counts);
        baseline::pyright_baseline_json(&run, "2026-11-05T00:00:00+00:00", "test")
    }
}

#[test]
fn baselines_from_the_policy_commit_gate_only_new_problems_r94_r49_t42() {
    let Some(p) = project("baselines_gate_only_new_problems", Some(POLICY), false) else {
        return;
    };
    // Without baselines: the pre-existing error and failure both fail full.
    p.commit("python project");
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(step(&report, "ruff")["status"], "pass", "{report}");
    assert_eq!(step(&report, "pyright")["status"], "fail", "{report}");
    assert_eq!(step(&report, "pytest")["status"], "fail", "{report}");
    for needle in [
        "1 pyright error(s).",
        "  - legacy.py:1  reportAssignmentType",
        "1 failing test(s).",
        "  - tests/test_app.py::test_old",
        "rerun: cd py && uv run pytest tests/test_app.py::test_old",
    ] {
        assert!(out.contains(needle), "{needle:?} in\n{out}");
    }
    let job = report["job_id"].as_str().unwrap();
    let log = std::fs::read_to_string(p.sb.state().join("jobs").join(job).join("job.log")).unwrap();
    assert!(log.contains("setup \"uv sync\": ran"), "R45: {log}");

    // Baselines recorded and merged: full passes.
    let pyright = p.pyright_baseline();
    std::fs::write(p.py().join(baseline::PYRIGHT_FILE), &pyright).unwrap();
    std::fs::write(
        p.py().join(baseline::PYTEST_FILE),
        baseline::pytest_baseline_json(
            &["tests/test_app.py::test_old".to_owned()].into(),
            "2026-11-05T00:00:00+00:00",
            "test",
        ),
    )
    .unwrap();
    p.commit("baselines");
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}\n{report}");

    // A new type error and a new failing test fail fast; the new failure is
    // re-run in isolation (R94). A baseline the change itself extends does
    // not apply: the policy commit's does (R49, L2).
    p.write(
        "py/app.py",
        &format!("{APP}\n\ndef name() -> str:\n    return 1\n"),
    );
    p.write(
        "py/tests/test_app.py",
        &format!("{TESTS}\n\ndef test_new():\n    assert add(2, 2) == 5\n"),
    );
    p.write(
        "py/.pytest-baseline.json",
        &baseline::pytest_baseline_json(
            &[
                "tests/test_app.py::test_old".to_owned(),
                "tests/test_app.py::test_new".to_owned(),
            ]
            .into(),
            "x",
            "x",
        ),
    );
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(report["tier"], "fast");
    for needle in [
        "POLICY: this branch changes py/.pytest-baseline.json",
        "1 new pyright error(s) not in the baseline (baseline 1, now 2):",
        "  - app.py  reportReturnType",
        "1 new failing test(s) not in the baseline (baseline 1, now 2):",
        "  - tests/test_app.py::test_new  [reproduced in isolation]",
        "rerun: cd py && uv run pytest tests/test_app.py::test_new",
    ] {
        assert!(out.contains(needle), "{needle:?} in\n{out}");
    }
    assert_eq!(step(&report, "ruff")["status"], "pass");
    assert_eq!(
        step(&report, "ruff")["scope"]["files"]["files"],
        serde_json::json!(["py/app.py", "py/tests/test_app.py"]),
        "ruff lints the changed Python files only (R60)"
    );
    let job = report["job_id"].as_str().unwrap();
    let pylog =
        std::fs::read_to_string(p.sb.state().join("jobs").join(job).join("pytest.log")).unwrap();
    assert!(
        pylog.contains("re-running 1 new failure(s) in isolation"),
        "{pylog}"
    );

    // A fixed baselined failure passes with a note; ruff fails on a change
    // it rejects.
    p.sb.git(&p.repo, &["reset", "-q", "--hard"]);
    p.write(
        "py/tests/test_app.py",
        "from app import add\n\n\ndef test_add():\n    assert add(1, 2) == 3\n",
    );
    p.write("py/tool.py", "import os\nx=1\n");
    let (code, out, report) = p.check(&["check", "--wait"]);
    assert_eq!(code, Some(1), "{out}");
    assert_eq!(step(&report, "pytest")["status"], "pass", "{report}");
    assert!(
        step(&report, "pytest")["message"]
            .as_str()
            .unwrap()
            .contains("1 baselined failure(s) now pass"),
        "{report}"
    );
    assert_eq!(step(&report, "pyright")["status"], "pass", "{report}");
    assert_eq!(step(&report, "ruff")["status"], "fail", "{report}");
    assert!(out.contains("F401"), "ruff output in the tail: {out}");
    assert!(
        step(&report, "ruff")["command"]
            .as_str()
            .unwrap()
            .ends_with(" ruff tests/test_app.py tool.py"),
        "{report}"
    );
    // R42: the Python steps left no file in the checkout (no __pycache__,
    // .ruff_cache or .pytest_cache), or the step would be an error.
    assert_ne!(report["verdict"], "error", "{report}");
}

#[test]
fn a_python_tool_missing_from_the_venv_is_a_setup_error_r46() {
    let Some(uv) = tools::which("uv") else {
        tools::skip("a_python_tool_missing_from_the_venv", "uv is not on PATH");
        return;
    };
    // No wheels needed: the project has no dependencies, so its .venv has
    // no pytest.
    let sb = Sandbox::new();
    let repo = sb.repo("app");
    sb.commit_file(
        &repo,
        "pyproject.toml",
        "[project]\nname = \"app\"\nversion = \"0.1.0\"\nrequires-python = \">=3.11\"\n",
        "py",
    );
    let env = sb.env();
    tools::run(
        &uv,
        &["lock", "-q"],
        &repo,
        &env,
        &tools::offline_env(&sb.root()),
    );
    sb.commit_file(
        &repo,
        "tollgate.toml",
        "version = 1\n[[setup]]\nname = \"uv sync\"\nrun = \"uv sync --frozen\"\nwhen = [\"uv.lock\"]\n[[step]]\nname = \"pytest\"\nkind = \"pytest-baseline\"\n",
        "policy",
    );
    sb.git(&repo, &["add", "uv.lock"]);
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "lock"]);
    sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n{}",
        tools::job_config(&[&uv])
    ));
    let r = sb.tollgate(&repo, &["check", "--tier", "full", "--wait"]);
    let report = sb.report(&job_id(&r.out));
    if tools::which("pytest").is_some() {
        // A pytest on the job PATH would be used (uv run falls back to it).
        return;
    }
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert_eq!(report["cause"], "setup", "{report}");
    assert!(
        r.out
            .contains("pytest is not in the .venv of . nor on the job PATH"),
        "{}",
        r.out
    );
}

#[test]
fn detection_syncs_and_checks_a_python_root_t25_r65_r45() {
    let Some(p) = project("detection_syncs_and_checks_a_python_root", None, true) else {
        return;
    };
    p.commit("python project");
    let eff = p.sb.tollgate(&p.repo, &["config", "--effective"]);
    assert_eq!(eff.code, Some(0), "{}", eff.out);
    for needle in [
        "name = \"py uv sync\"",
        "run = \"uv sync --frozen\"",
        "kind = \"ruff\"",
        "kind = \"pyright-baseline\"",
        "kind = \"pytest-baseline\"",
    ] {
        assert!(eff.out.contains(needle), "{needle:?} in\n{}", eff.out);
    }
    let (code, out, report) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}\n{report}");
    for s in ["py ruff", "py pyright", "py pytest"] {
        assert_eq!(step(&report, s)["status"], "pass", "{s}: {report}");
    }
    let job = report["job_id"].as_str().unwrap();
    let log = std::fs::read_to_string(p.sb.state().join("jobs").join(job).join("job.log")).unwrap();
    assert!(log.contains("setup \"py uv sync\": ran"), "T25: {log}");
}

/// Runs tollgate with stdin and stdout on a new pty (an interactive
/// terminal) and stderr piped; returns the exit code and all output.
fn on_pty(
    sb: &Sandbox,
    cwd: &std::path::Path,
    args: &[&str],
    extra: &[(&str, PathBuf)],
) -> (Option<i32>, String) {
    use std::io::Read as _;
    use std::os::fd::{FromRawFd as _, OwnedFd};
    let (mut m, mut s) = (0, 0);
    // SAFETY: openpty writes two fds into the given ints; the null name,
    // termios and winsize pointers are allowed.
    let r = unsafe {
        libc::openpty(
            &raw mut m,
            &raw mut s,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(r, 0, "openpty");
    // SAFETY: both fds were just opened and are owned here only. CLOEXEC:
    // children other test threads fork must not keep the pty open.
    let (master, slave) = unsafe {
        libc::fcntl(m, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(s, libc::F_SETFD, libc::FD_CLOEXEC);
        (OwnedFd::from_raw_fd(m), OwnedFd::from_raw_fd(s))
    };
    let child = {
        let mut cmd = Command::new(support::BIN);
        cmd.env_clear()
            .current_dir(cwd)
            .args(args)
            .stdin(std::process::Stdio::from(slave.try_clone().unwrap()))
            .stdout(std::process::Stdio::from(slave))
            .stderr(std::process::Stdio::piped());
        for (k, v) in sb.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.spawn().unwrap()
    };
    let out = child.wait_with_output().unwrap();
    // SAFETY: `m` is the master fd owned by `master`.
    unsafe {
        libc::fcntl(m, libc::F_SETFL, libc::O_NONBLOCK);
    }
    let mut tty = Vec::new();
    let mut f = std::fs::File::from(master);
    let mut buf = [0u8; 4096];
    while let Ok(n) = f.read(&mut buf) {
        if n == 0 {
            break;
        }
        tty.extend_from_slice(&buf[..n]);
    }
    (
        out.status.code(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&tty).replace("\r\n", "\n"),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn baseline_record_needs_a_tty_and_a_clean_tree_and_matches_the_scripts_t42_r94() {
    let Some(p) = project("baseline_record", Some(POLICY), false) else {
        return;
    };
    p.commit("python project");
    let py = p.py();
    let offline = tools::offline_env(&p.sb.root());
    let extra: Vec<(&str, &str)> = offline
        .iter()
        .map(|(k, v)| (*k, v.to_str().unwrap()))
        .collect();
    // No TTY (Claude's Bash): refused.
    let r =
        p.sb.tollgate_with(&py, &["baseline", "record", "pyright"], &extra);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("needs an interactive terminal"), "{}", r.out);
    assert!(!py.join(baseline::PYRIGHT_FILE).exists());

    // A TTY but a dirty tree: refused.
    std::fs::write(py.join("app.py"), format!("{APP}# wip\n")).unwrap();
    let (code, out) = on_pty(&p.sb, &py, &["baseline", "record", "pytest"], &offline);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("the working tree is dirty"), "{out}");
    assert!(
        out.contains("git stash -u && tollgate baseline record pytest && git stash pop"),
        "{out}"
    );
    p.sb.git(&p.repo, &["checkout", "--", "py/app.py"]);

    // Clean, at a TTY: both baselines are recorded in the scripts' format.
    for (kind, msg) in [
        ("pyright", "Recorded 1 pre-existing pyright error(s) to "),
        ("pytest", "Recorded 1 pre-existing test failure(s) to "),
    ] {
        let (code, out) = on_pty(&p.sb, &py, &["baseline", "record", kind], &offline);
        assert_eq!(code, Some(0), "{out}");
        assert!(out.contains(msg), "{out}");
    }
    let read = |f: &str| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(py.join(f)).unwrap()).unwrap()
    };
    let pyright = read(baseline::PYRIGHT_FILE);
    let pytest = read(baseline::PYTEST_FILE);
    assert_eq!(
        pytest["tests"],
        serde_json::json!({"tests/test_app.py::test_old": true})
    );
    assert_eq!(pyright["total"], 1);
    assert_eq!(
        pyright["commit"].as_str().unwrap(),
        p.sb.git(&p.repo, &["rev-parse", "--short", "HEAD"])
    );

    // The scripts themselves, where this machine still has them, record the
    // same fingerprints (R94). They run as copies in the sandbox.
    let hooks = std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".claude/hooks"));
    let scripts = hooks
        .as_ref()
        .map(|h| (h.join("pyright-baseline.sh"), h.join("pytest-baseline.sh")))
        .filter(|(a, b)| a.is_file() && b.is_file() && tools::which("jq").is_some());
    if let Some((pr, pt)) = scripts {
        let copies = p.sb.root().join("scripts");
        tools::copy(&pr, &copies.join("pyright-baseline.sh"));
        tools::copy(&pt, &copies.join("pytest-baseline.sh"));
        let ours = (pyright.clone(), pytest.clone());
        p.sb.git(&p.repo, &["add", "-A"]);
        p.sb.git(&p.repo, &["commit", "-q", "--no-verify", "-m", "ours"]);
        let env = p.sb.env();
        for s in ["pyright-baseline.sh", "pytest-baseline.sh"] {
            tools::run(
                std::path::Path::new("bash"),
                &[copies.join(s).to_str().unwrap(), "--record"],
                &py,
                &env,
                &offline,
            );
        }
        let theirs = (read(baseline::PYRIGHT_FILE), read(baseline::PYTEST_FILE));
        assert_eq!(ours.0["counts"], theirs.0["counts"], "pyright fingerprints");
        assert_eq!(ours.0["total"], theirs.0["total"]);
        assert_eq!(ours.0["pyright"], theirs.0["pyright"]);
        assert_eq!(ours.1["tests"], theirs.1["tests"], "pytest node ids");
        assert_eq!(ours.1["total"], theirs.1["total"]);
    } else {
        tools::skip(
            "baseline_record (script comparison)",
            "~/.claude/hooks/*-baseline.sh or jq not present",
        );
    }

    // The recorded baselines, once merged, make full pass.
    p.commit("baselines");
    let (code, out, _) = p.check(&["check", "--tier", "full", "--wait"]);
    assert_eq!(code, Some(0), "{out}");
}
