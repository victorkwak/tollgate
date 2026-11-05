//! Shared helpers for integration tests: a sandbox HOME and real git repos.
//!
//! Every test points HOME, XDG dirs and git's global config into a temp
//! dir, so nothing reads or writes the real ~/.config, ~/.local or ~/.claude.

// Each test crate uses a different subset of these helpers.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use tollgate::env::EnvSnapshot;

/// A temp dir with a sandbox HOME.
pub struct Sandbox {
    pub tmp: tempfile::TempDir,
    pub home: PathBuf,
}

impl Sandbox {
    pub fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join(".gitconfig"),
            "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n",
        )
        .unwrap();
        Self { tmp, home }
    }

    /// The sandbox root (canonical).
    pub fn root(&self) -> PathBuf {
        self.home.parent().unwrap().to_owned()
    }

    /// Environment for tollgate code and git in the sandbox.
    pub fn env(&self) -> EnvSnapshot {
        let root = self.root();
        EnvSnapshot::from_pairs([
            ("PATH", std::env::var_os("PATH").unwrap_or_default()),
            ("HOME", self.home.clone().into_os_string()),
            ("XDG_STATE_HOME", root.join("state").into_os_string()),
            ("XDG_DATA_HOME", root.join("data").into_os_string()),
            ("XDG_CONFIG_HOME", root.join("config").into_os_string()),
            ("GIT_CONFIG_NOSYSTEM", "1".into()),
            ("LANG", "C".into()),
        ])
    }

    /// Runs real git in `dir` with the sandbox env plus `extra`.
    pub fn git_output(&self, dir: &Path, args: &[&str], extra: &[(&str, &OsStr)]) -> Output {
        let mut cmd = Command::new("git");
        cmd.env_clear();
        for (k, v) in self.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.current_dir(dir).args(args).output().unwrap()
    }

    /// Runs real git; panics on failure; returns trimmed stdout.
    pub fn git(&self, dir: &Path, args: &[&str]) -> String {
        self.git_with(dir, args, &[])
    }

    pub fn git_with(&self, dir: &Path, args: &[&str], extra: &[(&str, &OsStr)]) -> String {
        let out = self.git_output(dir, args, extra);
        assert!(
            out.status.success(),
            "git {args:?} in {}: {}",
            dir.display(),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap().trim().to_owned()
    }

    /// A new repo under the sandbox root with one commit.
    pub fn repo(&self, name: &str) -> PathBuf {
        let dir = self.root().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q"]);
        self.commit_file(&dir, "README", "hello\n", "init");
        dir
    }

    /// Writes `path`, stages it, commits; returns the commit id.
    pub fn commit_file(&self, repo: &Path, path: &str, content: &str, msg: &str) -> String {
        let file = repo.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, content).unwrap();
        self.git(repo, &["add", path]);
        self.git(repo, &["commit", "-q", "--no-verify", "-m", msg]);
        self.git(repo, &["rev-parse", "HEAD"])
    }
}

/// Canonicalizes the longest existing prefix of `p` (paths that may not
/// exist yet still compare equal across symlinked temp dirs).
pub fn norm(p: &Path) -> PathBuf {
    let mut existing = p.to_owned();
    let mut rest = Vec::new();
    while !existing.exists() {
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                rest.push(name.to_owned());
                existing = parent.to_owned();
            }
            _ => break,
        }
    }
    let mut out = existing.canonicalize().unwrap_or(existing);
    for part in rest.iter().rev() {
        out.push(part);
    }
    out
}

/// Writes an executable file through a child process. A file the test
/// process writes itself can stay open for writing in a child that another
/// test thread forks at that moment, and exec then fails with ETXTBSY
/// ("Text file busy"); a file written by `sh` has no such writer.
pub fn write_exe(path: &Path, content: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    let mut child = Command::new("sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success(), "write {}", path.display());
}

/// Options of [`write_workspace`].
#[derive(Debug, Clone, Copy, Default)]
pub struct Scratch {
    /// `b`'s unit test `tests::fails` fails.
    pub failing: bool,
}

/// Writes a two-crate Cargo workspace into `dir`: `a` dev-depends on `b`;
/// `a` has a doctest, a passing test and `tests::flaky`, which fails on
/// every other try (a counter file named by `FLAKY_COUNTER`; it passes when
/// that variable is unset); `b` has a unit test `tests::fails` and an
/// integration test binary `it`.
pub fn write_workspace(dir: &Path, opts: Scratch) {
    let files: &[(&str, &str)] = &[
        (
            "Cargo.toml",
            "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\nresolver = \"2\"\n",
        ),
        (
            "Cargo.lock",
            "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"a\"\nversion = \"0.1.0\"\ndependencies = [\n \"b\",\n]\n\n[[package]]\nname = \"b\"\nversion = \"0.1.0\"\n",
        ),
        (".gitignore", "target/\n"),
        (
            "crates/a/Cargo.toml",
            "[package]\nname = \"a\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dev-dependencies]\nb = { path = \"../b\" }\n",
        ),
        (
            "crates/a/src/lib.rs",
            r#"/// Adds one.
///
/// ```
/// assert_eq!(a::one(1), 2);
/// ```
pub fn one(x: u32) -> u32 {
    x + 1
}

#[cfg(test)]
mod tests {
    #[test]
    fn ok() {
        assert_eq!(super::one(b::two()), 3);
    }

    #[test]
    fn flaky() {
        let Ok(p) = std::env::var("FLAKY_COUNTER") else {
            return;
        };
        let n: u32 = std::fs::read_to_string(&p)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        std::fs::write(&p, (n + 1).to_string()).unwrap();
        assert!(n % 2 == 1, "fails on every other try");
    }
}
"#,
        ),
        (
            "crates/b/Cargo.toml",
            "[package]\nname = \"b\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        ),
        (
            "crates/b/tests/it.rs",
            "#[test]\nfn integration() {\n    assert_eq!(b::two(), 2);\n}\n",
        ),
    ];
    for (path, content) in files {
        let p = dir.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, content).unwrap();
    }
    write_b(dir, if opts.failing { 3 } else { 2 });
}

/// Rewrites `crates/b/src/lib.rs` so `tests::fails` expects `expected`
/// (it passes for 2).
pub fn write_b(dir: &Path, expected: u32) {
    let p = dir.join("crates/b/src/lib.rs");
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(
        p,
        format!(
            "/// Two.\npub fn two() -> u32 {{\n    2\n}}\n\n#[cfg(test)]\nmod tests {{\n    #[test]\n    fn fails() {{\n        assert_eq!(super::two(), {expected});\n    }}\n}}\n"
        ),
    )
    .unwrap();
}

impl Sandbox {
    /// A repo with the scratch workspace committed on `main`.
    pub fn rust_repo(&self, name: &str, opts: Scratch) -> PathBuf {
        let dir = self.root().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        self.git(&dir, &["init", "-q"]);
        write_workspace(&dir, opts);
        self.git(&dir, &["add", "-A"]);
        self.git(&dir, &["commit", "-q", "--no-verify", "-m", "workspace"]);
        dir
    }
}

/// The tollgate binary under test.
pub const BIN: &str = env!("CARGO_BIN_EXE_tollgate");

/// Output of a tollgate run: exit code and stdout + stderr.
#[derive(Debug)]
pub struct Run {
    pub code: Option<i32>,
    pub out: String,
}

impl Sandbox {
    /// Writes the host config (`$XDG_CONFIG_HOME/tollgate/config.toml`).
    pub fn host_config(&self, text: &str) {
        let p = self.root().join("config/tollgate/config.toml");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }

    /// The sandbox state dir (`$XDG_STATE_HOME/tollgate`).
    pub fn state(&self) -> PathBuf {
        self.root().join("state/tollgate")
    }

    /// Runs the tollgate binary in `cwd` with the sandbox env plus `extra`.
    pub fn tollgate_with(&self, cwd: &Path, args: &[&str], extra: &[(&str, &str)]) -> Run {
        let mut cmd = Command::new(BIN);
        cmd.env_clear()
            .current_dir(cwd)
            .args(args)
            .stdin(Stdio::null());
        for (k, v) in self.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        Run {
            code: out.status.code(),
            out: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    /// Runs the tollgate binary in `cwd` with the sandbox env.
    pub fn tollgate(&self, cwd: &Path, args: &[&str]) -> Run {
        self.tollgate_with(cwd, args, &[])
    }

    /// Job ids that exist, oldest first.
    pub fn jobs(&self) -> Vec<String> {
        let mut ids: Vec<String> = std::fs::read_dir(self.state().join("jobs"))
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                    .filter(|n| n.len() == 24 && n.as_bytes()[8] == b'-')
                    .collect()
            })
            .unwrap_or_default();
        ids.sort();
        ids
    }

    /// `jobs/<id>/report.json` as JSON.
    pub fn report(&self, job: &str) -> serde_json::Value {
        let p = self.state().join("jobs").join(job).join("report.json");
        serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
    }

    /// Number of record files.
    pub fn record_count(&self) -> usize {
        let Ok(rd) = std::fs::read_dir(self.state().join("results")) else {
            return 0;
        };
        rd.flatten()
            .map(|shard| std::fs::read_dir(shard.path()).map_or(0, |r| r.count()))
            .sum()
    }
}

/// The job id named in tollgate output (`job <id>`).
pub fn job_id(out: &str) -> String {
    out.split_whitespace()
        .skip_while(|w| *w != "job")
        .nth(1)
        .unwrap_or_else(|| panic!("no job id in:\n{out}"))
        .to_owned()
}

/// Kills runner processes a failed test left behind, with their steps.
fn kill_runners(jobs: &Path) {
    let Ok(rd) = std::fs::read_dir(jobs) else {
        return;
    };
    let Ok(table) = tollgate::procs::ProcTable::snapshot() else {
        return;
    };
    for e in rd.flatten() {
        let Ok(text) = std::fs::read_to_string(e.path().join("runner.pid")) else {
            continue;
        };
        let Ok(pid) = text.trim().parse::<i32>() else {
            continue;
        };
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
        if !String::from_utf8_lossy(&cmdline).contains("__run-job") {
            continue;
        }
        for p in table.descendants(pid) {
            let _ = tollgate::procs::signal(p, libc::SIGKILL);
        }
        let _ = tollgate::procs::signal(pid, libc::SIGKILL);
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        kill_runners(&self.root().join("state/tollgate/jobs"));
    }
}

/// Polls `cond` until it holds or `secs` pass.
pub fn eventually(secs: u64, mut cond: impl FnMut() -> bool) -> bool {
    let end = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < end {
        if cond() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    cond()
}

/// Every hook name `install` links (R2 minus `reference-transaction`, L1).
pub const HOOK_NAMES: &[&str] = &[
    "pre-commit",
    "pre-merge-commit",
    "pre-push",
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "prepare-commit-msg",
    "commit-msg",
    "post-commit",
    "pre-rebase",
    "post-checkout",
    "post-merge",
    "post-rewrite",
    "pre-auto-gc",
];

/// A test hooks dir of hard links to the built binary (R1). Hard links need
/// the binary's file system, so the dir lives in the target tmp dir, keyed
/// by the binary's inode and mtime; it is made once by an atomic rename and
/// shared by every test of this build.
pub fn test_hooks_dir() -> PathBuf {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(BIN).unwrap();
    let base = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let dir = base.join(format!(
        "hooks-{}-{}-{}",
        md.dev(),
        md.ino(),
        md.mtime_nsec() + md.mtime() * 1_000_000_000
    ));
    if dir.join("pre-commit").exists() {
        return dir;
    }
    let tmp = tempfile::tempdir_in(base).unwrap();
    for name in HOOK_NAMES {
        std::fs::hard_link(BIN, tmp.path().join(name)).unwrap();
    }
    let staged = tmp.keep();
    if std::fs::rename(&staged, &dir).is_err() {
        // Another test made it first.
        let _ = std::fs::remove_dir_all(&staged);
    }
    dir
}

impl Sandbox {
    /// The hook injection (R3) pointing at [`test_hooks_dir`].
    pub fn injection(&self) -> Vec<(&'static str, std::ffi::OsString)> {
        vec![
            ("GIT_CONFIG_COUNT", "1".into()),
            ("GIT_CONFIG_KEY_0", "core.hooksPath".into()),
            ("GIT_CONFIG_VALUE_0", test_hooks_dir().into_os_string()),
        ]
    }

    /// Runs git in `dir` under the injection plus `extra`.
    pub fn hooked_with(&self, dir: &Path, args: &[&str], extra: &[(&str, &str)]) -> Run {
        let inj = self.injection();
        let mut all: Vec<(&str, &OsStr)> = inj.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
        all.extend(extra.iter().map(|(k, v)| (*k, OsStr::new(*v))));
        let out = self.git_output(dir, args, &all);
        Run {
            code: out.status.code(),
            out: format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        }
    }

    /// Runs git in `dir` under the injection.
    pub fn hooked(&self, dir: &Path, args: &[&str]) -> Run {
        self.hooked_with(dir, args, &[])
    }

    /// Host config with the sandbox root as the scope root, a tiny disk
    /// floor (tests run in /tmp) and `extra` appended.
    pub fn scoped_host(&self, extra: &str) {
        self.host_config(&format!(
            "[scope]\nroots = [\"{}\"]\n{extra}\n[verify]\nmin_free = \"1M\"\n",
            self.root().display()
        ));
    }
}

impl Sandbox {
    /// Runs hook link `name` from [`test_hooks_dir`] directly in `repo`
    /// with the sandbox env, the injection and `extra`.
    pub fn run_hook(
        &self,
        repo: &Path,
        name: &str,
        extra: &[(&str, &str)],
    ) -> std::process::Output {
        let mut cmd = std::process::Command::new(test_hooks_dir().join(name));
        cmd.env_clear()
            .current_dir(repo)
            .stdin(std::process::Stdio::null());
        for (k, v) in self.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in self.injection() {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd.output().unwrap()
    }
}

/// A sandbox with tollgate installed (fake claude, sandbox settings).
pub struct Armed {
    pub sb: Sandbox,
    pub path: String,
}

impl Armed {
    pub fn new() -> Self {
        let sb = Sandbox::new();
        let bin_dir = sb.root().join("bin");
        write_exe(
            &bin_dir.join("claude"),
            "#!/bin/sh\necho '2.1.317 (Claude Code)'\n",
        );
        sb.host_config("[verify]\nmin_free = \"1M\"\n");
        std::fs::create_dir_all(sb.home.join(".claude")).unwrap();
        std::fs::write(sb.home.join(".claude/settings.json"), "{}\n").unwrap();
        let a = Self {
            path: format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap()),
            sb,
        };
        let r = a.install();
        assert_eq!(r.0, Some(0), "{}", r.1);
        a
    }

    pub fn install(&self) -> (Option<i32>, String) {
        let out = self
            .cmd(Path::new(BIN), &["install", "--yes"], &[])
            .output()
            .unwrap();
        (
            out.status.code(),
            format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ),
        )
    }

    pub fn data(&self) -> PathBuf {
        self.sb.root().join("data/tollgate")
    }

    pub fn bin(&self) -> PathBuf {
        self.data().join("bin/tollgate")
    }

    pub fn cmd(&self, program: &Path, args: &[&str], extra: &[(&str, &str)]) -> Command {
        let mut cmd = Command::new(program);
        cmd.env_clear().current_dir(self.sb.root()).args(args);
        for (k, v) in self.sb.env().iter() {
            cmd.env(k, v);
        }
        let root = self.sb.root();
        cmd.env("PATH", &self.path)
            .env("TMPDIR", &root)
            .env("TOLLGATE_TEST_INSTALL", "1");
        let hooks = self.data().join("hooks");
        cmd.env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "core.hooksPath")
            .env("GIT_CONFIG_VALUE_0", hooks);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd
    }

    /// Runs the installed guard on `input`; returns (exit, stdout, stderr).
    pub fn guard_raw(&self, input: &str, extra: &[(&str, &str)]) -> (Option<i32>, String, String) {
        let mut child = self
            .cmd(&self.bin(), &["guard"], extra)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        (
            out.status.code(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    pub fn bash(&self, command: &str) -> (Option<i32>, String, String) {
        self.bash_with(command, &[])
    }

    pub fn bash_with(
        &self,
        command: &str,
        extra: &[(&str, &str)],
    ) -> (Option<i32>, String, String) {
        let input = serde_json::json!({
            "session_id": "s",
            "hook_event_name": "PreToolUse",
            "cwd": self.sb.root(),
            "tool_name": "Bash",
            "tool_input": {"command": command, "description": "d"},
        });
        self.guard_raw(&input.to_string(), extra)
    }

    pub fn write(&self, file: &str) -> (Option<i32>, String, String) {
        let input = serde_json::json!({
            "cwd": self.sb.root(),
            "tool_name": "Write",
            "tool_input": {"file_path": file, "content": "x"},
        });
        self.guard_raw(&input.to_string(), &[])
    }
}
