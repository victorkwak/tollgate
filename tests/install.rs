//! `install`, `uninstall`, `doctor` on a sandbox settings file (T43, R1-R3,
//! R39, R95-R97, L10). A fake `claude` prints a version; nothing reads or
//! writes the real ~/.claude.

mod support;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use support::{BIN, Run, Sandbox, write_exe};

const FIXTURE: &str = r#"{
  "model": "opus",
  "env": {
    "FOO": "1"
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "~/.claude/hooks/pre-commit-checks.sh"
          }
        ]
      }
    ]
  },
  "statusLine": {
    "type": "command"
  }
}
"#;

struct Env {
    sb: Sandbox,
    bin_dir: PathBuf,
}

impl Env {
    fn new(claude_version: &str) -> Self {
        let sb = Sandbox::new();
        let bin_dir = sb.root().join("bin");
        write_exe(
            &bin_dir.join("claude"),
            &format!("#!/bin/sh\necho '{claude_version} (Claude Code)'\n"),
        );
        sb.host_config("[verify]\nmin_free = \"1M\"\n");
        let settings = sb.home.join(".claude/settings.json");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        std::fs::write(&settings, FIXTURE).unwrap();
        Self { sb, bin_dir }
    }

    fn settings(&self) -> PathBuf {
        self.sb.home.join(".claude/settings.json")
    }

    fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(self.settings()).unwrap()).unwrap()
    }

    fn data(&self) -> PathBuf {
        self.sb.root().join("data/tollgate")
    }

    fn path_var(&self) -> String {
        format!(
            "{}:{}",
            self.bin_dir.display(),
            std::env::var("PATH").unwrap()
        )
    }

    /// Runs `program` with the sandbox env and the fake claude first on
    /// PATH. The sandbox settings are not the account's real ones, so
    /// `--yes` needs no terminal for them (L10); nothing else opens it.
    fn run(&self, program: &Path, args: &[&str], extra: &[(&str, &str)]) -> Run {
        let root = self.sb.root();
        let path = self.path_var();
        let mut all: Vec<(&str, &str)> = vec![("PATH", path.as_str())];
        all.extend_from_slice(extra);
        let mut cmd = std::process::Command::new(program);
        cmd.env_clear()
            .current_dir(&root)
            .args(args)
            .stdin(std::process::Stdio::null());
        for (k, v) in self.sb.env().iter() {
            cmd.env(k, v);
        }
        for (k, v) in all {
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
}

fn ino(p: &Path) -> u64 {
    std::fs::metadata(p).unwrap().ino()
}

#[test]
fn install_adds_tagged_entries_and_uninstall_removes_exactly_them_t43_r95_r96() {
    let e = Env::new("2.1.317");
    let r = e.run(Path::new(BIN), &["install", "--yes"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    // R95c: a unified diff before the edit.
    assert!(
        r.out.contains("+++ ") && r.out.contains("+    \"GIT_CONFIG_COUNT\": \"1\","),
        "{}",
        r.out
    );
    // R1: the private copy and its hard links.
    let bin = e.data().join("bin/tollgate");
    assert_eq!(std::fs::read(&bin).unwrap(), std::fs::read(BIN).unwrap());
    for name in support::HOOK_NAMES {
        assert_eq!(ino(&e.data().join("hooks").join(name)), ino(&bin), "{name}");
    }
    assert!(!e.data().join("hooks/reference-transaction").exists(), "L1");
    // R3, R23: the injection and two tagged guard entries; R95c: the old
    // script entry is gone; other keys keep their order.
    let v = e.json();
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["model", "env", "hooks", "statusLine"]);
    assert_eq!(v["env"]["FOO"], "1");
    assert_eq!(v["env"]["GIT_CONFIG_KEY_0"], "core.hooksPath");
    assert_eq!(
        v["env"]["GIT_CONFIG_VALUE_0"],
        e.data().join("hooks").to_str().unwrap()
    );
    let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(groups.len(), 2, "{v:#}");
    for g in groups {
        let h = &g["hooks"][0];
        assert!(h["command"].as_str().unwrap().contains("tollgate:"), "{h}");
        assert!(h["command"].as_str().unwrap().contains(" guard"), "{h}");
        assert_eq!(h["timeout"], 10);
        assert_eq!(h["onFailure"], "block");
    }
    assert!(!v.to_string().contains("pre-commit-checks.sh"));
    // A backup of the original, install.json, the host config kept.
    let backups: Vec<_> = std::fs::read_dir(e.settings().parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|d| d.file_name().to_string_lossy().contains("tollgate-bak-"))
        .collect();
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), FIXTURE);
    // Item 10: the settings env may hold secrets.
    assert_eq!(
        std::fs::metadata(backups[0].path()).unwrap().mode() & 0o777,
        0o600
    );
    let rec: serde_json::Value =
        serde_json::from_slice(&std::fs::read(e.data().join("install.json")).unwrap()).unwrap();
    assert_eq!(rec["hooks"].as_array().unwrap().len(), 14);
    // A second install changes nothing in the settings.
    let r = e.run(Path::new(BIN), &["install", "--yes"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains("already has the injection and the guard"),
        "{}",
        r.out
    );

    // An edit made after install survives uninstall (R96).
    let mut v = e.json();
    v["env"]["LATER"] = serde_json::json!("kept");
    v["permissions"] = serde_json::json!({"allow": ["Bash(ls)"]});
    std::fs::write(e.settings(), serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let r = e.run(&bin, &["uninstall", "--yes"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let v = e.json();
    assert_eq!(v["env"], serde_json::json!({"FOO": "1", "LATER": "kept"}));
    assert_eq!(v["permissions"]["allow"][0], "Bash(ls)");
    let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["model", "env", "hooks", "statusLine", "permissions"]);
    // The old script is gone, so its entry is not put back.
    assert!(r.out.contains("not restored"), "{}", r.out);
    assert!(!e.data().exists(), "uninstall removes the data dir");
    assert!(e.sb.root().join("config/tollgate/config.toml").exists());
}

#[test]
fn reinstall_after_a_new_build_refreshes_the_copy_and_links_t43_r1() {
    let e = Env::new("2.1.317");
    let r = e.run(Path::new(BIN), &["install", "--yes"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let bin = e.data().join("bin/tollgate");
    let old = ino(&bin);
    // A "new build" on PATH: the same program with different bytes.
    let newer = e.sb.root().join("newbuild/tollgate");
    std::fs::create_dir_all(newer.parent().unwrap()).unwrap();
    let status = std::process::Command::new("sh")
        .args(["-c", "cp \"$1\" \"$2\" && printf x >> \"$2\"", "sh", BIN])
        .arg(&newer)
        .status()
        .unwrap();
    assert!(status.success());
    let r = e.run(&newer, &["install", "--yes"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_ne!(ino(&bin), old);
    assert_eq!(std::fs::read(&bin).unwrap(), std::fs::read(&newer).unwrap());
    for name in support::HOOK_NAMES {
        assert_eq!(ino(&e.data().join("hooks").join(name)), ino(&bin), "{name}");
    }
}

#[test]
fn settings_are_never_edited_without_confirmation_l10_r95b() {
    let e = Env::new("2.1.317");
    // Without --yes and without a TTY: refused; the links are made. (The
    // real settings refuse --yes without a TTY too: a unit test in
    // src/install covers that, since no test may touch ~/.claude.)
    let r = e.run(Path::new(BIN), &["install"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("L10"), "{}", r.out);
    assert_eq!(std::fs::read_to_string(e.settings()).unwrap(), FIXTURE);
    assert!(e.data().join("hooks/pre-commit").exists());
    // The old test switch opens nothing and is not needed for a sandbox.
    let r = e.run(
        Path::new(BIN),
        &["install"],
        &[("TOLLGATE_TEST_INSTALL", "1"), ("TMPDIR", "/")],
    );
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert_eq!(std::fs::read_to_string(e.settings()).unwrap(), FIXTURE);
    // R95b: Claude Code without onFailure: block.
    let old = Env::new("2.1.200");
    let r = old.run(Path::new(BIN), &["install", "--yes"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("older than 2.1.295"), "{}", r.out);
    assert!(!old.data().exists());
}

#[test]
fn doctor_reports_links_settings_injection_and_stale_locks_r39_r97() {
    let e = Env::new("2.1.317");
    let r = e.run(Path::new(BIN), &["install", "--yes"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let bin = e.data().join("bin/tollgate");
    let r = e.run(&bin, &["doctor"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    for want in [
        "ok   hooks: 14 links",
        "ok   dirs: hooks use the recorded state dir",
        "ok   settings:",
        "ok   claude: 2.1.317",
        "ok   git: git version",
    ] {
        assert!(r.out.contains(want), "no {want:?} in:\n{}", r.out);
    }
    // R52, R97: step tools are looked up on the job PATH, which steps get,
    // not on this process's PATH. A uv that only this PATH has is no help.
    let fake_uv = e.bin_dir.join("uv");
    write_exe(&fake_uv, "#!/bin/sh\necho 'uv 9.9.9-fake'\n");
    let uv_line = |out: &str| {
        out.lines()
            .find(|l| l.contains(" uv: "))
            .unwrap_or_else(|| panic!("no uv line in:\n{out}"))
            .to_owned()
    };
    let line = uv_line(&e.run(&bin, &["doctor"], &[]).out);
    assert!(
        !(line.starts_with("ok") && line.contains(fake_uv.to_str().unwrap())),
        "{line}"
    );
    if line.starts_with("warn") {
        let fix = format!("add {} to [job] path_prepend", e.bin_dir.display());
        assert!(line.contains(&fix), "{line}");
    }
    e.sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n[job]\npath_prepend = [{:?}]\n",
        e.bin_dir.display().to_string()
    ));
    let r = e.run(&bin, &["doctor"], &[]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert_eq!(
        uv_line(&r.out),
        format!("ok   uv: uv 9.9.9-fake ({})", fake_uv.display())
    );
    // --injection, as a Claude Bash call sees it, never names the key.
    let hooks = e.data().join("hooks");
    let inj = [
        ("GIT_CONFIG_COUNT", "1"),
        ("GIT_CONFIG_KEY_0", "core.hooksPath"),
        ("GIT_CONFIG_VALUE_0", hooks.to_str().unwrap()),
    ];
    let r = e.run(&bin, &["doctor", "--injection"], &inj);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(r.out.contains("ok   injection"), "{}", r.out);
    assert!(!r.out.to_lowercase().contains("hookspath"), "{}", r.out);
    let r = e.run(&bin, &["doctor", "--injection"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("FAIL injection"), "{}", r.out);
    // A broken link fails.
    std::fs::remove_file(hooks.join("post-merge")).unwrap();
    let r = e.run(&bin, &["doctor"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(
        r.out.contains("FAIL hooks") && r.out.contains("post-merge"),
        "{}",
        r.out
    );

    // R39: a lock older than 2 minutes with no git working in the repo is
    // stale; a fresh one is not reported.
    let repo = e.sb.repo("r");
    std::fs::write(repo.join(".git/index.lock"), b"").unwrap();
    let r = e.run(&bin, &["doctor", "--repo", repo.to_str().unwrap()], &[]);
    // The written host config trusts no remote, so this repo has none.
    assert!(
        r.out
            .contains("warn remotes: no trusted remote (scope.remotes names none"),
        "{}",
        r.out
    );
    assert!(
        r.out.contains("ok   locks: no git lock file older"),
        "{}",
        r.out
    );
    let st = std::process::Command::new("touch")
        .args(["-d", "5 minutes ago"])
        .arg(repo.join(".git/index.lock"))
        .status()
        .unwrap();
    assert!(st.success());
    let r = e.run(&bin, &["doctor", "--repo", repo.to_str().unwrap()], &[]);
    assert!(
        r.out.contains("FAIL locks: stale:") && r.out.contains("index.lock"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("rm "), "R39: never names rm: {}", r.out);
}

#[test]
fn uninstall_keeps_the_binary_while_the_settings_name_it_r96() {
    let e = Env::new("2.1.317");
    // Install without the settings edit (no confirmation), then a hand
    // edit registers the guard: uninstall must not remove the binary the
    // settings still run.
    let r = e.run(Path::new(BIN), &["install"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    let bin = e.data().join("bin/tollgate");
    let mut v = e.json();
    v["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
        serde_json::json!(format!("{} guard # tollgate:guard", bin.display()));
    std::fs::write(e.settings(), serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let r = e.run(&bin, &["uninstall", "--yes"], &[]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("still names tollgate"), "{}", r.out);
    assert!(bin.exists());
}
