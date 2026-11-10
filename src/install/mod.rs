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
//! L10, item 29: install and uninstall run only at an interactive
//! terminal (stdin and stdout), and the settings file is never edited
//! without a confirmation of its diff. No flag or variable changes that.
//! The file is resolved once ([`settings_file`]): what is shown is what
//! is written.

pub mod diff;
pub mod doctor;
pub mod settings;
pub mod settings_file;

use std::collections::BTreeMap;
use std::ffi::OsStr;
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
use settings_file::SettingsFile;

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
    /// The git binary every tollgate git call of this install runs, by
    /// absolute path (item 39): found at install on `[job] path_prepend`
    /// and the system dirs, never on `PATH`. `None` in records of older
    /// builds (doctor asks for `tollgate install`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<PathBuf>,
    /// An install made or found the index of repos with trusted-remote
    /// records (item 33, secreview note 27). A later install never makes
    /// it again: a missing index then means records were deleted with
    /// it, which only `tollgate remotes forget` accepts.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub trust_index: bool,
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

/// L10, item 29: `install` and `uninstall` run only for a person at an
/// interactive terminal: stdin (the answer) and stdout (the diff and the
/// question) are TTYs. Claude's Bash has none. No flag, variable or path
/// rule opens a way around it: Claude Code's active config dir can be
/// anywhere (`CLAUDE_CONFIG_DIR`), so no file is safe to edit unasked.
/// Nor inside a Claude Code session ([`claude_session`]).
fn interactive(env: &EnvSnapshot, what: &str) -> Result<(), String> {
    if let Some(var) = claude_session(env) {
        return Err(format!(
            "runs inside a Claude Code session ({var} is set; review note 1); it changes the Claude Code settings only after a person confirms the diff; run tollgate {what} in your own terminal"
        ));
    }
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        return Ok(());
    }
    Err(format!(
        "needs an interactive terminal on stdin and stdout (L10, item 29); it changes the Claude Code settings only after a person confirms the diff; run tollgate {what} in your own terminal"
    ))
}

/// Review note 1: the variable that shows a command runs in a Claude Code
/// session, if one is set. Claude Code sets `CLAUDECODE` for every
/// command its Bash tool runs, and what those start inherits it, so a
/// pty an agent makes (`script`, `dtach`, `faketty`, a terminal it opens)
/// passes the TTY test but not this one. A person's own terminal, also
/// one the Claude desktop app opens, has none. Neither test holds against
/// same-user code that drops the variable and makes a pty from a file the
/// guard does not read (21d); the guard denies the Bash ways to do it.
#[must_use]
pub fn claude_session(env: &EnvSnapshot) -> Option<&'static str> {
    ["CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT"]
        .into_iter()
        .find(|v| env.get(v).is_some())
}

/// Asks on the terminal (stdout, which [`interactive`] made sure is one);
/// anything but a yes is a no.
fn confirm(question: &str) -> bool {
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes")
}

/// The settings text and its parsed value; `{}` for a file that does not
/// exist.
fn parse_settings(file: &SettingsFile) -> Result<(String, serde_json::Value), String> {
    if !file.existed() {
        return Ok((String::new(), serde_json::json!({})));
    }
    let text = file.text()?;
    let v = serde_json::from_str(text).map_err(|e| format!("{}: {e}", file.describe()))?;
    Ok((text.to_owned(), v))
}

/// How an edit of the settings went.
enum Edit {
    Unchanged,
    Applied,
    Declined,
}

/// Shows the diff of a settings edit and applies it after a yes (L10).
/// The file is the one read and shown: a swap since then writes nothing
/// (item 29). `backup` names the backup to write next to it first (kept
/// when it exists).
fn edit_settings(
    file: &SettingsFile,
    old: &str,
    new: &str,
    backup: Option<&OsStr>,
) -> Result<Edit, String> {
    let d = diff::unified(
        old,
        new,
        &file.describe(),
        &format!("{} (new)", file.describe()),
        3,
    );
    if d.is_empty() {
        return Ok(Edit::Unchanged);
    }
    print!("{d}");
    if !confirm(&format!("apply this change to {}?", file.describe())) {
        return Ok(Edit::Declined);
    }
    file.check_unchanged()?;
    if let Some(b) = backup {
        file.write_backup(b)?;
    }
    file.replace(new)?;
    Ok(Edit::Applied)
}

fn fail(msg: impl std::fmt::Display) -> u8 {
    eprintln!("tollgate install: {msg}");
    exit::FAIL
}

/// `tollgate install` (R95), at an interactive terminal only (L10, item
/// 29).
pub fn install(ctx: &Ctx) -> u8 {
    if let Err(e) = interactive(&ctx.env, "install") {
        return fail(e);
    }
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
    let mut status = exit::OK;
    // The index of repos with trusted-remote records (item 33): made by
    // the first install only.
    let made_index = previous.as_ref().is_some_and(|p| p.trust_index);
    let trust_index = match crate::remote_record::ensure_index(&dirs, !made_index) {
        Ok(crate::remote_record::IndexSetup::Present) => true,
        Ok(crate::remote_record::IndexSetup::Created(n)) => {
            println!(
                "trusted remotes: started the index of repos with trusted-remote records ({n} records)"
            );
            true
        }
        Ok(crate::remote_record::IndexSetup::Missing(file)) => {
            eprintln!(
                "tollgate install: the index {} of repos with trusted-remote records is missing (an earlier install made it), so every gated command denies: a repo whose record was deleted with it cannot be told from a new one. Install does not make it again; to accept the loss, run tollgate remotes forget in a repo from your own terminal (item 33)",
                file.display()
            );
            status = exit::FAIL;
            true
        }
        Err(e) => {
            eprintln!("tollgate install: trusted remotes: {e}");
            status = exit::FAIL;
            made_index
        }
    };
    let env = injection(&hooks_dir);
    // Item 39: the git the hooks and jobs run, fixed now.
    let prepend: Vec<PathBuf> = HostConfig::load(&dirs)
        .map(|h| h.config.job.path_prepend)
        .unwrap_or_default()
        .iter()
        .map(|p| dirs.expand_tilde(p))
        .collect();
    let Some(git) = crate::gitx::find_git(&prepend) else {
        return fail(format!(
            "no git in [job] path_prepend or {} (item 39: tollgate runs git by an absolute path)",
            crate::gitx::SYSTEM_GIT_DIRS.join(", ")
        ));
    };
    println!("git: {}", git.display());
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
        git: Some(git),
        trust_index,
    };
    // (c) the settings edit, on the file resolved once (item 29).
    let path = settings_path(&ctx.env, &dirs);
    match SettingsFile::open(&path).and_then(|f| parse_settings(&f).map(|p| (f, p))) {
        Err(e) => {
            eprintln!("tollgate install: {e}");
            status = exit::FAIL;
        }
        Ok((file, (old_text, old))) => {
            let mut new = old.clone();
            let command = settings::guard_command(&binary);
            let prev_settings = previous.as_ref().and_then(|p| p.settings.as_ref());
            match settings::apply_install(&mut new, &path, &env, &command, prev_settings) {
                Err(e) => {
                    eprintln!("tollgate install: {e}");
                    status = exit::FAIL;
                }
                Ok(mut srec) => {
                    let changed = new != old;
                    // The backup sits next to the file the settings path
                    // leads to, where it is written through the same dir.
                    let real_dir = file.real().parent().map(Path::to_owned);
                    if changed
                        && file.existed()
                        && srec
                            .backup
                            .as_ref()
                            .is_none_or(|b| b.parent() != real_dir.as_deref())
                    {
                        let stamp = jiff::Timestamp::now().strftime("%Y%m%dT%H%M%S");
                        let mut name = file.real().file_name().unwrap_or_default().to_owned();
                        name.push(format!(".tollgate-bak-{stamp}"));
                        srec.backup = Some(file.real().with_file_name(name));
                    }
                    let backup = if changed && file.existed() {
                        srec.backup.as_ref().and_then(|b| b.file_name())
                    } else {
                        None
                    };
                    let shown_new = if changed {
                        settings::to_text(&new, &old_text)
                    } else {
                        old_text.clone()
                    };
                    match edit_settings(&file, &old_text, &shown_new, backup) {
                        Ok(Edit::Unchanged) => {
                            println!(
                                "settings: {} already has the injection and the guard",
                                file.describe()
                            );
                            record.settings = Some(srec);
                        }
                        Ok(Edit::Applied) => {
                            println!(
                                "settings: updated {}{}",
                                file.describe(),
                                srec.backup
                                    .as_ref()
                                    .map(|b| format!(" (backup {})", b.display()))
                                    .unwrap_or_default()
                            );
                            record.settings = Some(srec);
                        }
                        Ok(Edit::Declined) => {
                            eprintln!("tollgate install: settings not changed: not confirmed");
                            status = exit::FAIL;
                        }
                        Err(e) => {
                            eprintln!("tollgate install: settings not changed: {e}");
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

/// `tollgate uninstall` (R96), at an interactive terminal only (L10, item
/// 29).
pub fn uninstall(ctx: &Ctx) -> u8 {
    let fail = |m: String| {
        eprintln!("tollgate uninstall: {m}");
        exit::FAIL
    };
    if let Err(e) = interactive(&ctx.env, "uninstall") {
        return fail(e);
    }
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
    // The settings file, resolved once (item 29): the edit, its check and
    // the final read below all go through it.
    let path = record
        .settings
        .as_ref()
        .map_or_else(|| settings_path(&ctx.env, &dirs), |s| s.path.clone());
    let file = match SettingsFile::open(&path) {
        Ok(f) => f,
        Err(e) => return fail(format!("{e}; nothing removed")),
    };
    if let Some(srec) = &record.settings {
        let edit = parse_settings(&file).and_then(|(old_text, old)| {
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
                    match edit_settings(&file, &old_text, &new_text, None) {
                        Ok(Edit::Applied | Edit::Unchanged) => println!(
                            "settings: removed tollgate's entries from {}",
                            file.describe()
                        ),
                        Ok(Edit::Declined) => {
                            return fail(
                                "settings not changed (not confirmed); nothing removed".into(),
                            );
                        }
                        Err(e) => return fail(format!("{e}; nothing removed")),
                    }
                } else {
                    println!("settings: no tollgate entries left in {}", file.describe());
                }
            }
            Err(e) => {
                // R96: the backup only when the structural edit fails.
                let Some(backup) = &srec.backup else {
                    return fail(format!("{e}; no backup to restore; fix the file by hand"));
                };
                let backup_text = match file.read_backup(backup) {
                    Ok(t) => t,
                    Err(b) => return fail(format!("{e}; {b}")),
                };
                let old_text = file.text_lossy();
                eprintln!(
                    "tollgate uninstall: {e}; the backup {} would replace it:",
                    backup.display()
                );
                match edit_settings(&file, &old_text, &backup_text, None) {
                    Ok(Edit::Applied | Edit::Unchanged) => {
                        println!("settings: restored {}", backup.display());
                    }
                    Ok(Edit::Declined) => {
                        return fail(
                            "settings not changed (not confirmed); nothing removed".into(),
                        );
                    }
                    Err(e) => return fail(format!("{e}; nothing removed")),
                }
            }
        }
    }
    // The guard must not stay registered for a binary that is gone: with
    // onFailure: block every Bash call would fail. A file that cannot be
    // read keeps the data dir too.
    let text = match file.read_now() {
        Ok(t) => t.unwrap_or_default(),
        Err(e) => return fail(format!("{e}; the data dir is kept")),
    };
    if text.contains(&format!("# {}", settings::MARKER))
        || text.contains(&*record.binary.to_string_lossy())
        || text.contains(&*record.hooks_dir.to_string_lossy())
    {
        return fail(format!(
            "{} still names tollgate's guard or hooks dir; remove those entries first (the data dir is kept)",
            file.describe()
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
