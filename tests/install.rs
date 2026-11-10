//! `install`, `uninstall`, `doctor` on a sandbox settings file (T43, R1-R3,
//! R39, R95-R97, L10). A fake `claude` prints a version; nothing reads or
//! writes the real ~/.claude.

mod support;

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use support::{BIN, Run, Sandbox, pty, write_exe};

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

    /// `program args` with the sandbox env, the fake claude first on PATH
    /// and `extra`; no stdio set.
    fn cmd(&self, program: &Path, args: &[&str], extra: &[(&str, &str)]) -> std::process::Command {
        let path = self.path_var();
        let mut cmd = std::process::Command::new(program);
        cmd.env_clear().current_dir(self.sb.root()).args(args);
        for (k, v) in self.sb.env().iter() {
            cmd.env(k, v);
        }
        cmd.env("PATH", path);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        cmd
    }

    /// Runs `program` at an interactive terminal (a pty), as a person
    /// would, answering its questions with `answers` (L10, item 29).
    fn tty(&self, program: &Path, args: &[&str], answers: &[&str]) -> Run {
        pty::run(self.cmd(program, args, &[]), pty::Streams::All, answers)
    }

    /// Runs `program` without a terminal (stdin is /dev/null), as an
    /// agent's Bash does.
    fn run(&self, program: &Path, args: &[&str], extra: &[(&str, &str)]) -> Run {
        let out = self
            .cmd(program, args, extra)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
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
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
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
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
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
    let r = e.tty(&bin, &["uninstall"], &["y"]);
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
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
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
    let r = e.tty(&newer, &["install"], &["y"]);
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
    // Without a terminal: refused before anything is done (item 29; S17
    // tries the ways around it). `--yes` is gone.
    for args in [&["install"][..], &["install", "--yes"], &["uninstall"]] {
        let r = e.run(Path::new(BIN), args, &[]);
        assert_ne!(r.code, Some(0), "{args:?}: {}", r.out);
        assert_eq!(std::fs::read_to_string(e.settings()).unwrap(), FIXTURE);
        assert!(!e.data().exists(), "{args:?}: {}", r.out);
    }
    let r = e.run(Path::new(BIN), &["install"], &[]);
    assert!(r.out.contains("interactive terminal"), "{}", r.out);
    // A pty an agent makes (script, dtach, faketty) passes the TTY test,
    // but the command still runs in the Claude Code session, which marks
    // its environment: refused before any question (review note 1).
    for args in [&["install"][..], &["uninstall"]] {
        let cmd = e.cmd(Path::new(BIN), args, &[("CLAUDECODE", "1")]);
        let r = pty::run(cmd, pty::Streams::All, &["y"]);
        assert_ne!(r.code, Some(0), "{args:?}: {}", r.out);
        assert!(r.out.contains("Claude Code session"), "{}", r.out);
        assert!(!r.out.contains("[y/N]"), "{}", r.out);
        assert_eq!(std::fs::read_to_string(e.settings()).unwrap(), FIXTURE);
        assert!(!e.data().exists(), "{args:?}: {}", r.out);
    }
    // At a terminal, a no (or anything but a yes) keeps the settings; the
    // copy and links are made.
    for answer in ["n", "", "yy"] {
        let r = e.tty(Path::new(BIN), &["install"], &[answer]);
        assert_eq!(r.code, Some(1), "{answer:?}: {}", r.out);
        assert!(r.out.contains("not confirmed"), "{}", r.out);
        assert!(r.out.contains("[y/N]"), "{}", r.out);
        assert_eq!(std::fs::read_to_string(e.settings()).unwrap(), FIXTURE);
        assert!(e.data().join("hooks/pre-commit").exists());
    }
    // R95b: Claude Code without onFailure: block.
    let old = Env::new("2.1.200");
    let r = old.tty(Path::new(BIN), &["install"], &["y"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("older than 2.1.295"), "{}", r.out);
    assert!(!old.data().exists());
}

#[test]
fn doctor_reports_links_settings_injection_and_stale_locks_r39_r97() {
    let e = Env::new("2.1.317");
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
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
    support::backdate(&repo.join(".git/index.lock"), 300);
    let r = e.run(&bin, &["doctor", "--repo", repo.to_str().unwrap()], &[]);
    // macOS cannot tell whether a live git owns the lock, so it only warns.
    let stale = if cfg!(target_os = "linux") {
        "FAIL locks: stale:"
    } else {
        "warn locks:"
    };
    assert!(
        r.out.contains(stale) && r.out.contains("index.lock"),
        "{}",
        r.out
    );
    assert!(!r.out.contains("rm "), "R39: never names rm: {}", r.out);
}

/// Item 35, review note 12: doctor names each host tool config jobs would
/// read with its blake3, fails while the host config does not approve
/// that content (every job fails then too), and is ok once it does.
#[test]
fn doctor_names_unapproved_host_tool_configs_item35() {
    let e = Env::new("2.1.317");
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let bin = e.data().join("bin/tollgate");
    let r = e.run(&bin, &["doctor"], &[]);
    assert!(!r.out.contains("host tool config:"), "{}", r.out);
    let config = e.sb.home.join(".cargo/config.toml");
    std::fs::create_dir_all(config.parent().unwrap()).unwrap();
    let text = "[net]\nretry = 3\n";
    std::fs::write(&config, text).unwrap();
    let hash = blake3::hash(text.as_bytes()).to_hex().to_string();
    let r = e.run(&bin, &["doctor"], &[]);
    assert_ne!(r.code, Some(0), "{}", r.out);
    let want = format!(
        "FAIL host tool config: {} is not approved (blake3 {hash})",
        config.display()
    );
    assert!(r.out.contains(&want), "no {want:?} in:\n{}", r.out);
    e.sb.host_config(&format!(
        "[verify]\nmin_free = \"1M\"\n[job.host_tool_configs]\n\"~/.cargo/config.toml\" = \"{hash}\"\n"
    ));
    let r = e.run(&bin, &["doctor"], &[]);
    let want = format!("ok   host tool config: {} approved", config.display());
    assert!(r.out.contains(&want), "no {want:?} in:\n{}", r.out);
    // Review note 20: uv's user config is one too.
    let uv = e.sb.home.join(".config/uv/uv.toml");
    std::fs::create_dir_all(uv.parent().unwrap()).unwrap();
    std::fs::write(&uv, text).unwrap();
    let r = e.run(&bin, &["doctor"], &[]);
    let want = format!(
        "FAIL host tool config: {} is not approved (blake3 {hash})",
        uv.display()
    );
    assert!(r.out.contains(&want), "no {want:?} in:\n{}", r.out);
}

/// Item 48: a remote that reaches a trusted mirror through a symlink (or
/// a trailing `/`, `..`) is not trusted, since git reads the spelled path
/// later; doctor names the canonical path to set. A `scope.trusted_paths`
/// entry that is not canonical trusts nothing, and doctor names the
/// canonical path to write instead.
#[test]
fn doctor_names_the_canonical_path_of_a_respelled_trusted_mirror_item48() {
    let e = Env::new("2.1.317");
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    let bin = e.data().join("bin/tollgate");
    let root = e.sb.root();
    let mirror = root.join("remotes/m.git");
    let other = root.join("remotes/o.git");
    for bare in [&mirror, &other] {
        std::fs::create_dir_all(bare).unwrap();
        e.sb.git(bare, &["init", "-q", "--bare"]);
    }
    let link = root.join("link.git");
    let cfg_link = root.join("cfg-link.git");
    std::os::unix::fs::symlink(&mirror, &link).unwrap();
    std::os::unix::fs::symlink(&other, &cfg_link).unwrap();
    e.sb.host_config(&format!(
        "[scope]\ntrusted_paths = [{:?}, {:?}]\n[verify]\nmin_free = \"1M\"\n",
        mirror.display().to_string(),
        cfg_link.display().to_string()
    ));
    let repo = e.sb.repo("r");
    e.sb.git(&repo, &["remote", "add", "origin", link.to_str().unwrap()]);
    let r = e.run(&bin, &["doctor", "--repo", repo.to_str().unwrap()], &[]);
    for want in [
        "warn remotes: no trusted remote".to_owned(),
        format!(
            "warn remotes: remote origin: {} reaches the trusted path {} by another spelling",
            link.display(),
            mirror.display()
        ),
        format!("git remote set-url origin {}", mirror.display()),
        format!(
            "warn scope: scope.trusted_paths entry {} is not its canonical path; it trusts nothing. Write {}",
            cfg_link.display(),
            other.display()
        ),
    ] {
        assert!(r.out.contains(&want), "no {want:?} in:\n{}", r.out);
    }
    // The canonical spelling is trusted and draws no warning.
    e.sb.git(
        &repo,
        &["remote", "set-url", "origin", mirror.to_str().unwrap()],
    );
    let r = e.run(&bin, &["doctor", "--repo", repo.to_str().unwrap()], &[]);
    assert!(r.out.contains("ok   remotes: trusted: origin"), "{}", r.out);
    assert!(!r.out.contains("another spelling"), "{}", r.out);
}

#[test]
fn uninstall_keeps_the_binary_while_the_settings_name_it_r96() {
    let e = Env::new("2.1.317");
    // Install without the settings edit (declined), then a hand edit
    // registers the guard: uninstall must not remove the binary the
    // settings still run.
    let r = e.tty(Path::new(BIN), &["install"], &["n"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    let bin = e.data().join("bin/tollgate");
    let mut v = e.json();
    v["hooks"]["PreToolUse"][0]["hooks"][0]["command"] =
        serde_json::json!(format!("{} guard # tollgate:guard", bin.display()));
    std::fs::write(e.settings(), serde_json::to_string_pretty(&v).unwrap()).unwrap();
    let r = e.tty(&bin, &["uninstall"], &["y"]);
    assert_eq!(r.code, Some(1), "{}", r.out);
    assert!(r.out.contains("still names tollgate"), "{}", r.out);
    assert!(bin.exists());
}

/// Item 29: a settings file that is a symlink (a dotfiles checkout) is
/// resolved once, at a terminal: the diff names where it leads, the
/// target is edited, the link stays, and the backup sits next to the
/// target. Uninstall reads and restores through the same resolution.
#[test]
fn a_symlinked_settings_file_is_edited_at_its_target_item29() {
    let e = Env::new("2.1.317");
    let dotfiles = e.sb.root().join("dotfiles");
    std::fs::create_dir_all(&dotfiles).unwrap();
    let target = dotfiles.join("claude.json");
    std::fs::rename(e.settings(), &target).unwrap();
    std::os::unix::fs::symlink(&target, e.settings()).unwrap();
    let r = e.tty(Path::new(BIN), &["install"], &["y"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        r.out.contains(&format!("-> {}", target.display())),
        "{}",
        r.out
    );
    assert!(
        e.settings()
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        std::fs::read_to_string(&target)
            .unwrap()
            .contains("core.hooksPath")
    );
    let backups: Vec<_> = std::fs::read_dir(&dotfiles)
        .unwrap()
        .flatten()
        .filter(|d| d.file_name().to_string_lossy().contains("tollgate-bak-"))
        .collect();
    assert_eq!(backups.len(), 1, "{}", r.out);
    assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), FIXTURE);
    let r = e.tty(&e.data().join("bin/tollgate"), &["uninstall"], &["y"]);
    assert_eq!(r.code, Some(0), "{}", r.out);
    assert!(
        e.settings()
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        !std::fs::read_to_string(&target)
            .unwrap()
            .contains("core.hooksPath")
    );
    assert!(!e.data().exists());
}
