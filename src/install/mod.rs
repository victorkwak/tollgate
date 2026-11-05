//! `install`, `uninstall`, `doctor`: the binary copy, the hook links, the
//! settings edit with markers, and `install.json` (R1-R3, R23, R95-R97,
//! L10).
//!
//! Layout under `$XDG_DATA_HOME/tollgate/`: `bin/tollgate` (a private copy
//! of the binary that cannot disappear with the PATH binary, R1),
//! `hooks/<name>` (hard links to that copy, R1, R2) and `install.json`
//! (what install wrote; the guard's self-check and `uninstall` read it,
//! R24, R96).
//!
//! L10: the settings file is never edited without an interactive
//! confirmation. Without a TTY on stdin, `--yes` is refused for the
//! account's real settings (any file under `<passwd home>/.claude/`,
//! symlinks resolved); tests use a sandbox settings file. No variable
//! changes that.

pub mod diff;
pub mod doctor;
pub mod settings;

use std::collections::BTreeMap;
use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use crate::cli::Ctx;
use crate::config::{HostConfig, Platform};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::fsx;

pub use settings::SettingsRecord;

/// Version of `install.json`.
pub const RECORD_VERSION: u32 = 1;

/// Oldest Claude Code with `onFailure: "block"` for hooks (R23, R95b).
pub const MIN_CLAUDE: (u32, u32, u32) = (2, 1, 295);

/// `install.json` (R24, R96).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstallRecord {
    /// [`RECORD_VERSION`].
    pub version: u32,
    /// The installed tollgate version.
    pub tollgate_version: String,
    /// When install last ran.
    pub installed_at: jiff::Timestamp,
    /// The installed copy (R1).
    pub binary: PathBuf,
    /// The hooks dir (R1).
    pub hooks_dir: PathBuf,
    /// Hook names linked (R2).
    pub hooks: Vec<String>,
    /// The injection, exactly as written to the settings (R3, R24).
    pub env: BTreeMap<String, String>,
    /// The settings edit, once it was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<SettingsRecord>,
    /// The dirs install used. Hooks of this install take their host
    /// config, scope roots and state dir from here, never from `HOME` or
    /// `XDG_*` in git's environment (R8). `None` in records of older
    /// builds: the guard and doctor then ask for `tollgate install`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dirs: Option<Dirs>,
}

impl InstallRecord {
    /// Reads `install.json`.
    pub fn read(dirs: &Dirs) -> Result<Self, String> {
        Self::read_at(&dirs.install_record())
    }

    /// Reads the record at `path`.
    pub fn read_at(path: &Path) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let rec: Self =
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
        if rec.version != RECORD_VERSION {
            return Err(format!(
                "{}: unknown version {}",
                path.display(),
                rec.version
            ));
        }
        Ok(rec)
    }

    /// Why the recorded dirs do not match `dirs` (the dirs of this
    /// process), if they do not (R8, R24).
    #[must_use]
    pub fn dirs_mismatch(&self, dirs: &Dirs) -> Option<String> {
        match &self.dirs {
            None => Some("install.json records no dirs (an older install)".into()),
            Some(d) if d != dirs => Some(format!(
                "install.json records config {}, state {}, data {}, but this environment has config {}, state {}, data {}",
                d.config_dir().display(),
                d.state_dir().display(),
                d.data_dir().display(),
                dirs.config_dir().display(),
                dirs.state_dir().display(),
                dirs.data_dir().display()
            )),
            Some(_) => None,
        }
    }

    fn write(&self, dirs: &Dirs) -> Result<(), String> {
        let path = dirs.install_record();
        let json = serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?;
        fsx::write_atomic(&path, &json).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// The injection for `hooks_dir` (R3).
#[must_use]
pub fn injection(hooks_dir: &Path) -> BTreeMap<String, String> {
    [
        ("GIT_CONFIG_COUNT", "1".to_owned()),
        ("GIT_CONFIG_KEY_0", "core.hooksPath".to_owned()),
        (
            "GIT_CONFIG_VALUE_0",
            hooks_dir.to_string_lossy().into_owned(),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}

/// `~/.claude/settings.json`, or `$CLAUDE_CONFIG_DIR/settings.json`.
#[must_use]
pub fn settings_path(env: &EnvSnapshot, dirs: &Dirs) -> PathBuf {
    env.get_nonempty("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| dirs.home().join(".claude"))
        .join("settings.json")
}

/// Identity of a file for the hard-link checks (R24).
#[must_use]
pub fn inode(path: &Path) -> Option<(u64, u64)> {
    std::fs::metadata(path).ok().map(|m| (m.dev(), m.ino()))
}

/// Hook names whose link in `hooks_dir` is missing or is not `binary`.
#[must_use]
pub fn bad_links(hooks_dir: &Path, binary: &Path, names: &[String]) -> Vec<String> {
    let want = inode(binary);
    names
        .iter()
        .filter(|n| want.is_none() || inode(&hooks_dir.join(n)) != want)
        .cloned()
        .collect()
}

/// (Re)creates `hooks_dir/<name>` as a hard link to `binary` for every
/// name, each by an atomic rename, and removes other files in the dir
/// (R1, R2). Returns the names it changed.
pub fn link_hooks(
    hooks_dir: &Path,
    binary: &Path,
    names: &[String],
) -> Result<Vec<String>, String> {
    fsx::ensure_dir(hooks_dir).map_err(|e| format!("{}: {e}", hooks_dir.display()))?;
    let want = inode(binary).ok_or_else(|| format!("{} is missing", binary.display()))?;
    let mut changed = Vec::new();
    for name in names {
        let link = hooks_dir.join(name);
        if inode(&link) == Some(want) {
            continue;
        }
        let tmp = hooks_dir.join(format!(".{name}.tmp-{}", fsx::unique_suffix()));
        std::fs::hard_link(binary, &tmp).map_err(|e| format!("link {}: {e}", tmp.display()))?;
        if let Err(e) = std::fs::rename(&tmp, &link) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("{}: {e}", link.display()));
        }
        changed.push(name.clone());
    }
    if let Ok(rd) = std::fs::read_dir(hooks_dir) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().into_owned();
            if !names.contains(&n) {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let bad = bad_links(hooks_dir, binary, names);
    if !bad.is_empty() {
        return Err(format!(
            "links still wrong after linking: {}",
            bad.join(", ")
        ));
    }
    Ok(changed)
}

/// Copies `exe` to `dest` by an atomic rename, unless it is that file.
fn copy_binary(exe: &Path, dest: &Path) -> Result<bool, String> {
    if let (Ok(a), Ok(b)) = (std::fs::canonicalize(exe), std::fs::canonicalize(dest))
        && a == b
    {
        return Ok(false);
    }
    let dir = dest.parent().ok_or("binary path has no parent")?;
    fsx::ensure_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let tmp = dir.join(format!(".tollgate.tmp-{}", fsx::unique_suffix()));
    std::fs::copy(exe, &tmp)
        .map_err(|e| format!("copy {} to {}: {e}", exe.display(), tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("{}: {e}", dest.display())
    })?;
    Ok(true)
}

/// Parses the first `x.y.z` in `text`.
#[must_use]
pub fn parse_version(text: &str) -> Option<(u32, u32, u32)> {
    text.split(|c: char| !(c.is_ascii_digit() || c == '.'))
        .find_map(|w| {
            let mut p = w.split('.');
            let v = (
                p.next()?.parse().ok()?,
                p.next()?.parse().ok()?,
                p.next()?.parse().ok()?,
            );
            Some(v)
        })
}

/// `claude --version` (R95b): the version text, or why it is unknown.
pub fn claude_version(env: &EnvSnapshot) -> Result<(String, (u32, u32, u32)), String> {
    let claude =
        crate::cache::toolcache::which("claude", env.get("PATH")).ok_or("claude is not on PATH")?;
    let mut cmd = Command::new(&claude);
    cmd.arg("--version")
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in env.iter() {
        cmd.env(k, v);
    }
    let out = cmd
        .output()
        .map_err(|e| format!("{}: {e}", claude.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let v = parse_version(&text).ok_or_else(|| format!("claude --version printed {text:?}"))?;
    Ok((text, v))
}

/// The home dir of this account from the password database, which no
/// environment variable changes.
#[must_use]
pub fn passwd_home() -> Option<PathBuf> {
    use std::ffi::CStr;
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: an all-zero passwd is a valid out-parameter.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: getpwuid_r writes into `pw` and `buf`, both owned and sized
    // here; `result` points at `pw` on success.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pw.pw_dir.is_null() {
        return None;
    }
    // SAFETY: pw_dir points into `buf` and is NUL-terminated.
    let dir = unsafe { CStr::from_ptr(pw.pw_dir) };
    Some(PathBuf::from(dir.to_string_lossy().into_owned()))
}

/// The canonical form of a file that may not exist yet: its parent made
/// canonical, the name kept.
fn canonical_file(path: &Path) -> PathBuf {
    match (path.parent(), path.file_name()) {
        (Some(dir), Some(name)) => {
            std::fs::canonicalize(dir).map_or_else(|_| path.to_owned(), |d| d.join(name))
        }
        _ => path.to_owned(),
    }
}

fn inside(path: &Path, dir: &Path) -> bool {
    path.starts_with(dir)
}

/// L10: may this run edit `settings` without asking? With a terminal on
/// stdin the user is there: `--yes` is their choice. Without one, see
/// [`yes_without_tty`].
fn yes_allowed(settings: &Path) -> Result<(), String> {
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    yes_without_tty(settings, passwd_home().as_deref())
}

/// Where `path` leads: the file a chain of symlinks names (a dangling link
/// too), with its parent dir made canonical.
fn resolve_file(path: &Path) -> PathBuf {
    let mut p = path.to_owned();
    for _ in 0..40 {
        match std::fs::read_link(&p) {
            Ok(t) if t.is_absolute() => p = t,
            Ok(t) => p = p.parent().map_or_else(|| t.clone(), |d| d.join(&t)),
            Err(_) => break,
        }
    }
    canonical_file(&p)
}

/// L10, item 9: without a terminal, `--yes` is refused for the account's
/// real settings: any file under `<home>/.claude/` (`home` from the
/// password database, which no variable changes), after symlinks of the
/// file and its dirs are resolved. Tests use a settings file elsewhere (a
/// sandbox `HOME`); no variable or `TMPDIR` rule opens the real one.
fn yes_without_tty(settings: &Path, home: Option<&Path>) -> Result<(), String> {
    let refuse = |why: &str| {
        Err(format!(
            "--yes needs a terminal on stdin for {} (L10: {why}); run tollgate install in your own terminal",
            settings.display()
        ))
    };
    let Some(home) = home else {
        return refuse("the account's home dir is unknown");
    };
    let real = home.join(".claude");
    let real = std::fs::canonicalize(&real).unwrap_or_else(|_| canonical_file(&real));
    if inside(&resolve_file(settings), &real) {
        return refuse("these are the account's real settings");
    }
    Ok(())
}

/// Asks on the terminal; false without one.
fn confirm(question: &str) -> bool {
    if !std::io::stdin().is_terminal() {
        return false;
    }
    eprint!("{question} [y/N] ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// Settings file text and parsed value; `{}` when it does not exist.
fn read_settings(path: &Path) -> Result<(String, serde_json::Value, bool), String> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let v: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok((text, v, true))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok((String::new(), serde_json::json!({}), false))
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Writes `text` to the settings file (through a symlink to its target),
/// keeping its mode.
fn write_settings(path: &Path, text: &str) -> Result<(), String> {
    let target = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_owned());
    let mode = std::fs::metadata(&target)
        .ok()
        .map(|m| m.permissions().mode());
    if let Some(dir) = target.parent() {
        fsx::ensure_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    fsx::write_atomic(&target, text.as_bytes())
        .map_err(|e| format!("{}: {e}", target.display()))?;
    if let Some(m) = mode {
        let _ = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(m));
    }
    Ok(())
}

/// How an edit of the settings went.
enum Edit {
    Unchanged,
    Applied,
    Declined(String),
}

/// Shows the diff of a settings edit and applies it after a yes (L10),
/// writing `backup` (path, original text) first when it does not exist.
fn edit_settings(
    path: &Path,
    old: &str,
    new: &str,
    yes: bool,
    backup: Option<&(PathBuf, String)>,
) -> Result<Edit, String> {
    let d = diff::unified(
        old,
        new,
        &path.display().to_string(),
        &format!("{} (new)", path.display()),
        3,
    );
    if d.is_empty() {
        return Ok(Edit::Unchanged);
    }
    eprint!("{d}");
    if yes {
        if let Err(e) = yes_allowed(path) {
            return Ok(Edit::Declined(e));
        }
    } else if !confirm(&format!("apply this change to {}?", path.display())) {
        return Ok(Edit::Declined(if std::io::stdin().is_terminal() {
            "not confirmed".into()
        } else {
            "the settings need this change and there is no terminal to confirm it (L10); run tollgate install in your own terminal".into()
        }));
    }
    if let Some((b, text)) = backup
        && !b.exists()
    {
        std::fs::write(b, text).map_err(|e| format!("backup {}: {e}", b.display()))?;
    }
    write_settings(path, new)?;
    Ok(Edit::Applied)
}

fn fail(msg: impl std::fmt::Display) -> u8 {
    eprintln!("tollgate install: {msg}");
    exit::FAIL
}

/// `tollgate install [--yes]` (R95).
pub fn install(ctx: &Ctx, yes: bool) -> u8 {
    let dirs = match Dirs::from_env(&ctx.env) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    // (b) Claude Code with onFailure: block.
    match claude_version(&ctx.env) {
        Ok((_, v)) if v >= MIN_CLAUDE => {}
        Ok((text, _)) => {
            return fail(format!(
                "Claude Code {text} is older than {}.{}.{}; hooks need onFailure: block (R23)",
                MIN_CLAUDE.0, MIN_CLAUDE.1, MIN_CLAUDE.2
            ));
        }
        Err(e) => return fail(format!("cannot check the Claude Code version (R95b): {e}")),
    }
    // (a) the private copy and the links.
    let binary = dirs.installed_binary();
    match copy_binary(&ctx.exe, &binary) {
        Ok(true) => println!("copied {} to {}", ctx.exe.display(), binary.display()),
        Ok(false) => println!("binary {} is the running copy", binary.display()),
        Err(e) => return fail(e),
    }
    let names: Vec<String> = crate::hook::installed_hook_names()
        .map(str::to_owned)
        .collect();
    let hooks_dir = dirs.hooks_dir();
    match link_hooks(&hooks_dir, &binary, &names) {
        Ok(changed) if changed.is_empty() => println!(
            "hooks: {} links in {} are current",
            names.len(),
            hooks_dir.display()
        ),
        Ok(changed) => println!(
            "hooks: linked {} in {}",
            changed.join(", "),
            hooks_dir.display()
        ),
        Err(e) => return fail(e),
    }
    let previous = InstallRecord::read(&dirs).ok();
    let env = injection(&hooks_dir);
    let mut record = InstallRecord {
        version: RECORD_VERSION,
        tollgate_version: crate::VERSION.to_owned(),
        installed_at: jiff::Timestamp::now(),
        binary: binary.clone(),
        hooks_dir: hooks_dir.clone(),
        hooks: names,
        env: env.clone(),
        settings: previous.as_ref().and_then(|p| p.settings.clone()),
        dirs: Some(dirs.clone()),
    };
    // (c) the settings edit.
    let path = settings_path(&ctx.env, &dirs);
    let mut status = exit::OK;
    match read_settings(&path) {
        Err(e) => {
            eprintln!("tollgate install: {e}");
            status = exit::FAIL;
        }
        Ok((old_text, old, existed)) => {
            let mut new = old.clone();
            let command = settings::guard_command(&binary);
            let prev_settings = previous.as_ref().and_then(|p| p.settings.as_ref());
            match settings::apply_install(&mut new, &path, &env, &command, prev_settings) {
                Err(e) => {
                    eprintln!("tollgate install: {e}");
                    status = exit::FAIL;
                }
                Ok(mut srec) => {
                    let new_text = settings::to_text(&new, &old_text);
                    if new != old && existed && srec.backup.is_none() {
                        let stamp = jiff::Timestamp::now().strftime("%Y%m%dT%H%M%S");
                        srec.backup = Some(PathBuf::from(format!(
                            "{}.tollgate-bak-{stamp}",
                            path.display()
                        )));
                    }
                    let backup = if new != old && existed {
                        srec.backup.clone().map(|b| (b, old_text.clone()))
                    } else {
                        None
                    };
                    let shown_new = if new == old {
                        old_text.clone()
                    } else {
                        new_text
                    };
                    match edit_settings(&path, &old_text, &shown_new, yes, backup.as_ref()) {
                        Ok(Edit::Unchanged) => {
                            println!(
                                "settings: {} already has the injection and the guard",
                                path.display()
                            );
                            record.settings = Some(srec);
                        }
                        Ok(Edit::Applied) => {
                            println!(
                                "settings: updated {}{}",
                                path.display(),
                                srec.backup
                                    .as_ref()
                                    .map(|b| format!(" (backup {})", b.display()))
                                    .unwrap_or_default()
                            );
                            record.settings = Some(srec);
                        }
                        Ok(Edit::Declined(why)) => {
                            eprintln!("tollgate install: settings not changed: {why}");
                            status = exit::FAIL;
                        }
                        Err(e) => {
                            eprintln!("tollgate install: {e}");
                            status = exit::FAIL;
                        }
                    }
                }
            }
        }
    }
    if let Err(e) = record.write(&dirs) {
        return fail(e);
    }
    // (d) the host config.
    let host = dirs.host_config_file();
    if !host.exists() {
        let r = fsx::ensure_dir(&dirs.config_dir()).and_then(|()| {
            fsx::write_atomic(&host, HostConfig::template(Platform::current()).as_bytes())
        });
        match r {
            Ok(()) => println!("wrote the host config {}; review it", host.display()),
            Err(e) => return fail(format!("{}: {e}", host.display())),
        }
    }
    // (e) doctor.
    println!();
    let _ = doctor::doctor(ctx, &doctor::Options::default());
    status
}

/// `tollgate uninstall [--yes]` (R96).
pub fn uninstall(ctx: &Ctx, yes: bool) -> u8 {
    let fail = |m: String| {
        eprintln!("tollgate uninstall: {m}");
        exit::FAIL
    };
    let dirs = match Dirs::from_env(&ctx.env) {
        Ok(d) => d,
        Err(e) => return fail(e.to_string()),
    };
    let record = match InstallRecord::read(&dirs) {
        Ok(r) => r,
        Err(e) => {
            return fail(format!(
                "no install record ({e}); nothing recorded to remove"
            ));
        }
    };
    if let Some(srec) = &record.settings {
        let path = &srec.path;
        let edit = read_settings(path).and_then(|(old_text, old, _)| {
            let mut new = old.clone();
            let notes = settings::apply_uninstall(&mut new, srec, dirs.home())?;
            let new_text = settings::to_text(&new, &old_text);
            Ok((old_text, new_text, new != old, notes))
        });
        match edit {
            Ok((old_text, new_text, changed, notes)) => {
                for n in &notes {
                    println!("settings: {n}");
                }
                if changed {
                    match edit_settings(path, &old_text, &new_text, yes, None) {
                        Ok(Edit::Applied | Edit::Unchanged) => println!(
                            "settings: removed tollgate's entries from {}",
                            path.display()
                        ),
                        Ok(Edit::Declined(why)) => {
                            return fail(format!("settings not changed ({why}); nothing removed"));
                        }
                        Err(e) => return fail(e),
                    }
                } else {
                    println!("settings: no tollgate entries left in {}", path.display());
                }
            }
            Err(e) => {
                // R96: the backup only when the structural edit fails.
                let Some(backup) = &srec.backup else {
                    return fail(format!("{e}; no backup to restore; fix the file by hand"));
                };
                let Ok(backup_text) = std::fs::read_to_string(backup) else {
                    return fail(format!(
                        "{e}; the backup {} cannot be read",
                        backup.display()
                    ));
                };
                let old_text = std::fs::read_to_string(path).unwrap_or_default();
                eprintln!(
                    "tollgate uninstall: {e}; the backup {} would replace it:",
                    backup.display()
                );
                match edit_settings(path, &old_text, &backup_text, yes, None) {
                    Ok(Edit::Applied | Edit::Unchanged) => {
                        println!("settings: restored {}", backup.display())
                    }
                    Ok(Edit::Declined(why)) => {
                        return fail(format!("settings not changed ({why}); nothing removed"));
                    }
                    Err(e) => return fail(e),
                }
            }
        }
    }
    // The guard must not stay registered for a binary that is gone: with
    // onFailure: block every Bash call would fail.
    let path = record
        .settings
        .as_ref()
        .map_or_else(|| settings_path(&ctx.env, &dirs), |s| s.path.clone());
    if let Ok(text) = std::fs::read_to_string(&path)
        && (text.contains(&format!("# {}", settings::MARKER))
            || text.contains(&*record.binary.to_string_lossy())
            || text.contains(&*record.hooks_dir.to_string_lossy()))
    {
        return fail(format!(
            "{} still names tollgate's guard or hooks dir; remove those entries first (the data dir is kept)",
            path.display()
        ));
    }
    let data = dirs.data_dir();
    if let Err(e) = std::fs::remove_dir_all(&data)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        return fail(format!("{}: {e}", data.display()));
    }
    println!(
        "removed {}; state, records and verify checkouts stay in {} (tollgate gc --all removes them)",
        data.display(),
        dirs.state_dir().display()
    );
    exit::OK
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_r95() {
        assert_eq!(parse_version("2.1.317 (Claude Code)"), Some((2, 1, 317)));
        assert_eq!(parse_version("claude v2.1.295"), Some((2, 1, 295)));
        assert_eq!(parse_version("none"), None);
        assert!((2, 1, 317) >= MIN_CLAUDE && (2, 0, 999) < MIN_CLAUDE);
    }

    /// L10, item 9: without a terminal, `--yes` never edits the account's
    /// real settings: anything under `<passwd home>/.claude/`, symlinks
    /// resolved, whatever `TMPDIR` or any variable says. `home` here is a
    /// temp dir standing in for the passwd home.
    #[test]
    fn yes_without_a_tty_never_reaches_the_real_settings_l10() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().canonicalize().unwrap().join("home");
        let real = home.join(".claude");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("settings.json"), "{}").unwrap();
        let sandbox = tmp.path().canonicalize().unwrap().join("sandbox/.claude");
        std::fs::create_dir_all(&sandbox).unwrap();
        let refused = |p: &Path| {
            let r = yes_without_tty(p, Some(&home));
            assert!(r.is_err(), "{} allowed", p.display());
            assert!(r.unwrap_err().contains("L10"));
        };
        // The real paths; the TMPDIR trick of item 9 has no input left:
        // the decision reads no variable.
        refused(&real.join("settings.json"));
        refused(&real.join("settings.local.json"));
        // A symlink to the real file, a dangling one into the real dir,
        // and a config dir that is a symlink to it.
        std::os::unix::fs::symlink(real.join("settings.json"), sandbox.join("a.json")).unwrap();
        refused(&sandbox.join("a.json"));
        std::os::unix::fs::symlink(real.join("new.json"), sandbox.join("b.json")).unwrap();
        refused(&sandbox.join("b.json"));
        let linked = tmp.path().join("cfg");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        refused(&linked.join("settings.json"));
        // A relative link chain into the real dir.
        std::os::unix::fs::symlink("a.json", sandbox.join("c.json")).unwrap();
        refused(&sandbox.join("c.json"));
        // A sandbox settings file is fine.
        assert_eq!(
            yes_without_tty(&sandbox.join("settings.json"), Some(&home)),
            Ok(())
        );
        // No passwd home: refused.
        assert!(yes_without_tty(&sandbox.join("settings.json"), None).is_err());
    }

    #[test]
    fn links_are_hard_links_to_the_copy_r1() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        std::fs::write(&bin, b"x").unwrap();
        let hooks = tmp.path().join("hooks");
        let names: Vec<String> = ["pre-commit", "post-commit"].map(String::from).to_vec();
        std::fs::create_dir_all(&hooks).unwrap();
        std::fs::write(hooks.join("reference-transaction"), b"old").unwrap();
        assert_eq!(link_hooks(&hooks, &bin, &names).unwrap(), names);
        assert!(bad_links(&hooks, &bin, &names).is_empty());
        assert!(!hooks.join("reference-transaction").exists());
        assert!(link_hooks(&hooks, &bin, &names).unwrap().is_empty());
        let other = tmp.path().join("other");
        std::fs::write(&other, b"y").unwrap();
        assert_eq!(bad_links(&hooks, &other, &names), names);
    }
}
