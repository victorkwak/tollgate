//! Claude Code PreToolUse guard (R23-R28, L8, L17, L18).
//!
//! Registered for `Bash` and `Write|Edit|MultiEdit|NotebookEdit` with
//! `timeout: 10` and `onFailure: block`. It exits only 0 or 2 (R23):
//!
//! - exit 2 with a one-line reason on stderr denies the call (R25, and R24
//!   for every Bash call while the gate is not armed, except the L8 repair
//!   commands);
//! - exit 0 with a `hookSpecificOutput` JSON asks (R26) and/or rewrites the
//!   input (R28, L17);
//! - exit 0 with no output allows.
//!
//! Self-check (R24) on every Bash call: the guard's environment has the
//! injection exactly as `install.json` recorded it, the guard runs as the
//! installed copy, and every hook link shares its inode. A missing hooks
//! dir or link is recreated first (L18) and logged to `repairs.log`.
//!
//! R28 as changed by L17: for a command that runs a waiting git command or
//! `tollgate check|wait|merge`, `updatedInput` raises `timeout` to 600000
//! and prefixes `export TOLLGATE_INLINE_CAP=<n>; ` (540, or the `fast`
//! budget for `run_in_background`). `export` instead of a bare assignment,
//! so the cap reaches git also after `cd x &&` or in a pipeline. The output
//! carries no `permissionDecision` for a plain rewrite, so Claude Code's own
//! permission rules still decide (UNVERIFIED that Claude Code applies
//! `updatedInput` without one; if not, the 100 s default cap stands, R28).

pub mod data;
pub mod rules;
pub mod shell;

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::config::glob::{self, GlobOpts};
use crate::config::{HostConfig, RepoConfig};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::install::{self, InstallRecord};
use crate::metrics;
use rules::{Context, Ruling};

/// The guard's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Exit code: 0 or 2 (R23).
    pub code: u8,
    /// JSON for Claude Code, when any.
    pub stdout: String,
    /// The deny reason or a note.
    pub stderr: String,
}

impl Answer {
    fn allow() -> Self {
        Self {
            code: exit::OK,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn deny(reason: impl Into<String>) -> Self {
        Self {
            code: exit::BLOCK,
            stdout: String::new(),
            stderr: reason.into(),
        }
    }
}

/// The R28 Bash timeout (ms).
pub const BASH_TIMEOUT_MS: u64 = 600_000;

/// The prefix the rewrite adds (L17).
const CAP_PREFIX: &str = "export TOLLGATE_INLINE_CAP=";

/// Default `tiers.full_refs` (L7).
const DEFAULT_FULL_REFS: &[&str] = &["main", "master", "integration/*"];

/// What the metrics log keeps of one guard call (item 50).
#[derive(Debug, Default)]
struct Note {
    tool: Option<String>,
    /// The command or file path; only its keyed hash is logged.
    subject: Option<String>,
    rule: Option<&'static str>,
    ask: bool,
    rewrite: bool,
}

impl Note {
    fn ruling(&mut self, ruling: &Ruling) {
        match ruling {
            Ruling::Allow => {}
            Ruling::Ask(r) => {
                self.rule = Some(r.rule);
                self.ask = true;
            }
            Ruling::Deny(r) => self.rule = Some(r.rule),
        }
    }
}

/// Runs the guard on PreToolUse input `input` (R23), and logs the
/// decision to the metrics log (item 50). The log never changes the
/// answer: [`metrics::record`] drops every error.
#[must_use]
pub fn guard(env: &EnvSnapshot, input: &[u8], exe: &Path, process_cwd: &Path) -> Answer {
    let start = std::time::Instant::now();
    let mut note = Note::default();
    let answer = answer(env, input, exe, process_cwd, &mut note);
    let us = u64::try_from(start.elapsed().as_micros()).unwrap_or(u64::MAX);
    if let Ok(dirs) = Dirs::from_env(env) {
        let decision = if answer.code != exit::OK {
            metrics::Decision::Deny
        } else if note.ask {
            metrics::Decision::Ask
        } else {
            metrics::Decision::Allow
        };
        // Only asks and denies carry the hash: it serves the false-deny
        // review (distinct commands per rule), and skipping it keeps the
        // key read off the common allow path (about 25 µs of the 55 µs
        // the log costs) and leaves fewer hashes to guess against.
        let cmd = note
            .subject
            .as_deref()
            .filter(|_| decision != metrics::Decision::Allow)
            .and_then(|s| metrics::keyed_hash(&dirs, s));
        metrics::record(
            &dirs,
            &[metrics::Event::Guard(metrics::GuardEvent {
                t: jiff::Timestamp::now(),
                tool: note.tool.unwrap_or_else(|| "?".into()),
                decision,
                rule: note.rule.map(str::to_owned),
                rewrite: note.rewrite,
                us,
                cmd,
            })],
        );
    }
    answer
}

fn answer(
    env: &EnvSnapshot,
    input: &[u8],
    exe: &Path,
    process_cwd: &Path,
    note: &mut Note,
) -> Answer {
    note.rule = Some("malformed-input");
    let Ok(v) = serde_json::from_slice::<Value>(input) else {
        return Answer::deny("tollgate guard: malformed hook input (not JSON)");
    };
    let Some(tool) = v.get("tool_name").and_then(Value::as_str) else {
        return Answer::deny("tollgate guard: malformed hook input (no tool_name)");
    };
    note.tool = Some(tool.chars().take(64).collect());
    let Some(tool_input) = v.get("tool_input").and_then(Value::as_object) else {
        return Answer::deny("tollgate guard: malformed hook input (no tool_input)");
    };
    let cwd = v
        .get("cwd")
        .and_then(Value::as_str)
        .map_or_else(|| process_cwd.to_owned(), PathBuf::from);
    let dirs = match Dirs::from_env(env) {
        Ok(d) => d,
        Err(e) => return Answer::deny(format!("tollgate guard: {e}")),
    };
    note.rule = None;
    let record = InstallRecord::read(&dirs);
    let ctx = context(env, &dirs, &cwd, record.as_ref().ok());
    match tool {
        "Bash" => {
            let Some(command) = tool_input.get("command").and_then(Value::as_str) else {
                note.rule = Some("malformed-input");
                return Answer::deny("tollgate guard: malformed Bash input (no command)");
            };
            note.subject = Some(command.to_owned());
            if let Err(reason) = self_check(env, &dirs, exe, record.as_ref()) {
                if rules::is_repair_command(&ctx, command) {
                    return Answer::allow();
                }
                note.rule = Some("not-armed");
                return Answer::deny(format!(
                    "tollgate: gate not armed ({reason}); run: tollgate install"
                ));
            }
            let ruling = rules::bash_ruling(&ctx, command);
            note.ruling(&ruling);
            if let Ruling::Deny(why) = &ruling {
                return Answer::deny(format!("tollgate guard: denied: {why}"));
            }
            let updated = rules::needs_long_timeout(&ctx, command)
                .then(|| rewrite(&dirs, tool_input, command));
            note.rewrite = updated.is_some();
            respond(&ruling, updated)
        }
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            let key = if tool == "NotebookEdit" {
                "notebook_path"
            } else {
                "file_path"
            };
            let Some(file) = tool_input.get(key).and_then(Value::as_str) else {
                note.rule = Some("malformed-input");
                return Answer::deny(format!("tollgate guard: malformed {tool} input (no {key})"));
            };
            note.subject = Some(file.to_owned());
            let ruling = rules::file_ruling(&ctx, file);
            note.ruling(&ruling);
            if let Ruling::Deny(why) = &ruling {
                return Answer::deny(format!("tollgate guard: denied: {why}"));
            }
            respond(&ruling, None)
        }
        _ => Answer::allow(),
    }
}

fn respond(ruling: &Ruling, updated: Option<Value>) -> Answer {
    let mut out = serde_json::Map::new();
    out.insert("hookEventName".into(), json!("PreToolUse"));
    if let Ruling::Ask(why) = ruling {
        out.insert("permissionDecision".into(), json!("ask"));
        out.insert(
            "permissionDecisionReason".into(),
            json!(format!("tollgate: {why}")),
        );
    }
    if let Some(u) = updated {
        out.insert("updatedInput".into(), u);
    }
    if out.len() == 1 {
        return Answer::allow();
    }
    Answer {
        code: exit::OK,
        stdout: json!({ "hookSpecificOutput": out }).to_string(),
        stderr: String::new(),
    }
}

/// R28/L17: the same input with the timeout raised and the cap exported.
fn rewrite(dirs: &Dirs, input: &serde_json::Map<String, Value>, command: &str) -> Value {
    let background = input.get("run_in_background").and_then(Value::as_bool) == Some(true);
    let cap = if background {
        HostConfig::load(dirs)
            .map(|h| h.config.budget.fast.get().as_secs())
            .unwrap_or(20 * 60)
    } else {
        crate::config::host::FOREGROUND_INLINE_CAP.as_secs()
    };
    let bare = match command.strip_prefix(CAP_PREFIX) {
        Some(rest) => rest.split_once("; ").map_or(rest, |(_, c)| c),
        None => command,
    };
    let mut out = input.clone();
    out.insert(
        "command".into(),
        json!(format!("{CAP_PREFIX}{cap}; {bare}")),
    );
    let timeout = input.get("timeout").and_then(Value::as_u64).unwrap_or(0);
    if timeout < BASH_TIMEOUT_MS {
        out.insert("timeout".into(), json!(BASH_TIMEOUT_MS));
    }
    Value::Object(out)
}

/// The repo root holding `path` (the nearest dir with a `.git` entry).
fn repo_root(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .skip(1)
        .find(|a| a.join(".git").exists())
        .map(Path::to_owned)
}

fn repo_config(root: &Path) -> RepoConfig {
    std::fs::read_to_string(root.join(crate::policy::CONFIG_FILE))
        .ok()
        .and_then(|t| RepoConfig::from_toml(&t).ok())
        .unwrap_or_default()
}

fn context(env: &EnvSnapshot, dirs: &Dirs, cwd: &Path, record: Option<&InstallRecord>) -> Context {
    let home = dirs.home().to_owned();
    let mut vars: Vec<(String, String)> =
        vec![("HOME".into(), home.to_string_lossy().into_owned())];
    for (var, default) in [
        ("XDG_STATE_HOME", ".local/state"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_CONFIG_HOME", ".config"),
    ] {
        let v = env.get_str(var).map_or_else(
            || home.join(default).to_string_lossy().into_owned(),
            str::to_owned,
        );
        vars.push((var.into(), v));
    }
    let mut protected = Vec::new();
    for d in [dirs.state_dir(), dirs.data_dir(), dirs.config_dir()] {
        if let Ok(c) = std::fs::canonicalize(&d)
            && c != d
        {
            protected.push(c);
        }
        protected.push(d);
    }
    let mut full: Vec<String> = DEFAULT_FULL_REFS.iter().map(|s| (*s).to_owned()).collect();
    if let Some(root) = repo_root(&cwd.join("x")) {
        full.extend(repo_config(&root).tiers.full_refs);
    }
    let full_refs = glob::compile(
        &full,
        GlobOpts {
            case_insensitive: true,
            literal_separator: false,
        },
    )
    .or_else(|_| {
        glob::compile(
            DEFAULT_FULL_REFS,
            GlobOpts {
                case_insensitive: true,
                literal_separator: false,
            },
        )
    })
    .unwrap_or_default();
    let mut names = vec![dirs.installed_binary().to_string_lossy().into_owned()];
    if let Some(r) = record {
        names.push(r.binary.to_string_lossy().into_owned());
    }
    Context {
        cwd: cwd.to_owned(),
        home,
        vars,
        protected,
        host_config: dirs.host_config_file(),
        full_refs,
        tollgate_names: names,
    }
}

/// R26: policy files (R71) and the repo's own hooks dir ask.
pub(crate) fn repo_rules(path: &Path) -> Option<(&'static str, String)> {
    let root = repo_root(path)?;
    let rel = path.strip_prefix(&root).ok()?;
    let config = repo_config(&root);
    if let Ok(m) = crate::policy::PolicyMatcher::new(&config)
        && m.is_policy_file(rel)
    {
        return Some((
            "policy-file-edit",
            format!(
                "edit of policy file {} (R26, R71; it applies after it merges to a full ref)",
                rel.display()
            ),
        ));
    }
    let env = EnvSnapshot::default();
    let layout = crate::gitx::RepoLayout::for_hook(&root, &env)?;
    if let Ok(crate::gitx::hooks_path::RepoHooks::Dir(d)) =
        crate::gitx::hooks_path::parse_hooks_path(&layout, &env, None)
        && d != layout.default_hooks_dir()
        && path.starts_with(&d)
    {
        return Some((
            "repo-hook-edit",
            format!(
                "edit of a repo hook in core.hooksPath {} (R26)",
                d.display()
            ),
        ));
    }
    None
}

/// R24 with the L18 repair. `Ok` when armed; `Err(reason)` otherwise.
fn self_check(
    env: &EnvSnapshot,
    dirs: &Dirs,
    exe: &Path,
    record: Result<&InstallRecord, &String>,
) -> Result<(), String> {
    let rec = record.map_err(|e| format!("no install record: {e}"))?;
    if let Some(why) = rec.dirs_mismatch(dirs) {
        return Err(why);
    }
    for (k, v) in &rec.env {
        if env.get_str(k) != Some(v.as_str()) {
            return Err(format!(
                "the session environment lacks {k} as installed; check ~/.claude/settings.json env and any settings.local.json"
            ));
        }
    }
    let Some(want) = install::inode(&rec.binary) else {
        return Err(format!(
            "the installed copy {} is missing",
            rec.binary.display()
        ));
    };
    if install::inode(exe) != Some(want) {
        return Err(format!(
            "the guard does not run as the installed copy {}",
            rec.binary.display()
        ));
    }
    let bad = install::bad_links(&rec.hooks_dir, &rec.binary, &rec.hooks);
    if bad.is_empty() {
        return Ok(());
    }
    // L18: missing (or dangling) links are recreated; a file with another
    // inode is not ours to replace.
    let foreign: Vec<&String> = bad
        .iter()
        .filter(|n| install::inode(&rec.hooks_dir.join(n)).is_some())
        .collect();
    if !foreign.is_empty() {
        let names: Vec<&str> = foreign.iter().map(|s| s.as_str()).collect();
        return Err(format!(
            "hook {} in {} is not a link to the installed copy",
            names.join(", "),
            rec.hooks_dir.display()
        ));
    }
    for n in &bad {
        // A dangling symlink blocks the new link's rename target check.
        let _ = std::fs::remove_file(rec.hooks_dir.join(n));
    }
    install::link_hooks(&rec.hooks_dir, &rec.binary, &rec.hooks)
        .map_err(|e| format!("repair failed: {e}"))?;
    let still = install::bad_links(&rec.hooks_dir, &rec.binary, &rec.hooks);
    if !still.is_empty() {
        return Err(format!("repair failed: {}", still.join(", ")));
    }
    let line = format!(
        "{} guard pid {} relinked {} in {}\n",
        jiff::Timestamp::now(),
        std::process::id(),
        bad.join(","),
        rec.hooks_dir.display()
    );
    let log = dirs.repairs_log();
    let _ = crate::fsx::ensure_dir(&dirs.state_dir());
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_raises_the_timeout_and_exports_the_cap_r28_l17() {
        let tmp = tempfile::tempdir().unwrap();
        let dirs =
            Dirs::from_env(&EnvSnapshot::from_pairs([("HOME", tmp.path().as_os_str())])).unwrap();
        let input = json!({"command": "cd r && git commit -m x", "timeout": 1000});
        let out = rewrite(&dirs, input.as_object().unwrap(), "cd r && git commit -m x");
        assert_eq!(
            out["command"],
            "export TOLLGATE_INLINE_CAP=540; cd r && git commit -m x"
        );
        assert_eq!(out["timeout"], BASH_TIMEOUT_MS);
        let bg = json!({"command": "git push", "run_in_background": true, "timeout": 900_000});
        let out = rewrite(
            &dirs,
            bg.as_object().unwrap(),
            "export TOLLGATE_INLINE_CAP=540; git push",
        );
        assert_eq!(out["command"], "export TOLLGATE_INLINE_CAP=1200; git push");
        assert_eq!(out["timeout"], 900_000);
    }

    #[test]
    fn malformed_input_blocks_r23() {
        let tmp = tempfile::tempdir().unwrap();
        let env = EnvSnapshot::from_pairs([("HOME", tmp.path().as_os_str())]);
        for input in [
            &b"not json"[..],
            b"{}",
            b"{\"tool_name\":\"Bash\"}",
            b"{\"tool_name\":\"Bash\",\"tool_input\":{}}",
        ] {
            let a = guard(&env, input, Path::new("/x"), tmp.path());
            assert_eq!(a.code, exit::BLOCK, "{}", String::from_utf8_lossy(input));
        }
        let a = guard(
            &env,
            br#"{"tool_name":"Read","tool_input":{"file_path":"/x"}}"#,
            Path::new("/x"),
            tmp.path(),
        );
        assert_eq!(a, Answer::allow());
    }
}
