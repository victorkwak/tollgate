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
//! Bash commands go through a closed grammar (G1-G8, [`walk`]): the
//! command is parsed as bash parses it ([`shell`]), and every simple
//! command in it must fit an allowed shape; anything else is denied with
//! the shape to use.
//!
//! R28 as changed by L17 and G6: for a command that runs a waiting git
//! command or `tollgate check|wait|merge`, `updatedInput` raises `timeout`
//! to 600000 and puts `export TOLLGATE_INLINE_CAP=<n>; ` (540, or the
//! `fast` budget for `run_in_background`) in front of the command exactly
//! as it was checked; the guard never removes or changes client text
//! (item 12). `export` instead of a bare assignment, so the cap reaches git
//! also after `cd x &&` or in a pipeline. A client may only lower the cap,
//! with a literal number in front of git or tollgate (G6). The output
//! carries no `permissionDecision` for a plain rewrite, so Claude Code's own
//! permission rules still decide (UNVERIFIED that Claude Code applies
//! `updatedInput` without one; if not, the 100 s default cap stands, R28).

mod cmds;
mod git;
mod gitopts;
pub mod paths;
mod progs;
pub mod rules;
mod runners;
pub mod shell;
mod transfer;
mod walk;

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::config::glob::{self, GlobOpts};
use crate::config::{HostConfig, RepoConfig};
use crate::dirs::Dirs;
use crate::env::EnvSnapshot;
use crate::exit;
use crate::install::{self, InstallRecord};
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

/// Runs the guard on PreToolUse input `input` (R23).
#[must_use]
pub fn guard(env: &EnvSnapshot, input: &[u8], exe: &Path, process_cwd: &Path) -> Answer {
    let Ok(v) = serde_json::from_slice::<Value>(input) else {
        return Answer::deny("tollgate guard: malformed hook input (not JSON)");
    };
    let Some(tool) = v.get("tool_name").and_then(Value::as_str) else {
        return Answer::deny("tollgate guard: malformed hook input (no tool_name)");
    };
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
    let record = InstallRecord::read(&dirs);
    let background = tool_input.get("run_in_background").and_then(Value::as_bool) == Some(true);
    let cap = inline_cap(&dirs, background);
    let ctx = context(env, &dirs, &cwd, record.as_ref().ok(), cap);
    match tool {
        "Bash" => {
            let Some(command) = tool_input.get("command").and_then(Value::as_str) else {
                return Answer::deny("tollgate guard: malformed Bash input (no command)");
            };
            if let Err(reason) = self_check(env, &dirs, exe, record.as_ref()) {
                if rules::is_repair_command(&ctx, command) {
                    return Answer::allow();
                }
                return Answer::deny(format!(
                    "tollgate: gate not armed ({reason}); run: tollgate install"
                ));
            }
            // Item 12: the rewrite puts its prefix in front of the exact
            // checked text and never removes any, so a command that
            // already starts with it imitates the guard.
            if command.trim_start().starts_with(CAP_PREFIX) {
                return Answer::deny(format!(
                    "tollgate guard: denied: the command starts with `{CAP_PREFIX}`, which only the guard adds; send the command without it"
                ));
            }
            let a = rules::assess(&ctx, command);
            if let Ruling::Deny(why) = &a.ruling {
                return Answer::deny(format!("tollgate guard: denied: {}", one_line(why)));
            }
            let updated = a.long_timeout.then(|| rewrite(tool_input, command, cap));
            respond(&a.ruling, updated)
        }
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            let key = if tool == "NotebookEdit" {
                "notebook_path"
            } else {
                "file_path"
            };
            let Some(file) = tool_input.get(key).and_then(Value::as_str) else {
                return Answer::deny(format!("tollgate guard: malformed {tool} input (no {key})"));
            };
            let ruling = rules::file_ruling(&ctx, file);
            if let Ruling::Deny(why) = &ruling {
                return Answer::deny(format!("tollgate guard: denied: {}", one_line(why)));
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

/// The cap the guard exports (L17): 540 s, or the `fast` budget for a
/// background call.
fn inline_cap(dirs: &Dirs, background: bool) -> u64 {
    if background {
        HostConfig::load(dirs)
            .map(|h| h.config.budget.fast.get().as_secs())
            .unwrap_or(20 * 60)
    } else {
        crate::config::host::FOREGROUND_INLINE_CAP.as_secs()
    }
}

/// A deny reason on one line (R23): newlines from quoted text become
/// `\n`.
fn one_line(why: &str) -> String {
    why.replace('\n', "\\n")
}

/// R28/L17: the same input with the timeout raised and the cap exported
/// in front of the command exactly as it was checked (item 12: client
/// text is never removed or changed).
fn rewrite(input: &serde_json::Map<String, Value>, command: &str, cap: u64) -> Value {
    let mut out = input.clone();
    out.insert(
        "command".into(),
        json!(format!("{CAP_PREFIX}{cap}; {command}")),
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

fn context(
    env: &EnvSnapshot,
    dirs: &Dirs,
    cwd: &Path,
    record: Option<&InstallRecord>,
    inline_cap: u64,
) -> Context {
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
    // Session values the rules may expand in paths, and CDPATH, which
    // makes a relative `cd` unpredictable (G8). CLAUDE_CONFIG_DIR picks
    // the user settings dir (R26).
    for var in ["TMPDIR", "CDPATH", "USER", "LOGNAME", "CLAUDE_CONFIG_DIR"] {
        if let Some(v) = env.get_str(var) {
            vars.push((var.into(), v.to_owned()));
        }
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
    // Item 35: the host config picks the tool homes and PATH dirs jobs
    // use; when it does not parse, jobs fail anyway, and the defaults
    // still count.
    let job = HostConfig::load(dirs)
        .map(|h| h.config.job)
        .unwrap_or_default();
    let mut tool_paths = Vec::new();
    for t in crate::runner::env::guarded_tool_paths(dirs, &job) {
        let c = paths::canon(&t);
        if c != t {
            tool_paths.push(c);
        }
        tool_paths.push(t);
    }
    Context {
        cwd: cwd.to_owned(),
        home,
        vars,
        protected,
        host_config: dirs.host_config_file(),
        tool_paths,
        full_refs,
        tollgate_names: names,
        inline_cap,
        git_env: EnvSnapshot::from_pairs(
            env.iter()
                .filter(|(k, _)| {
                    k.to_str().is_some_and(|k| {
                        k == "HOME" || k == "XDG_CONFIG_HOME" || k.starts_with("GIT_")
                    })
                })
                .map(|(k, v)| (k.to_owned(), v.to_owned())),
        ),
    }
}

/// R26: policy files (R71) and the repo's own hooks dir ask.
pub(crate) fn repo_rules(path: &Path) -> Option<String> {
    let root = repo_root(path)?;
    let rel = path.strip_prefix(&root).ok()?;
    let config = repo_config(&root);
    if let Ok(m) = crate::policy::PolicyMatcher::new(&config)
        && m.is_policy_file(rel)
    {
        return Some(format!(
            "edit of policy file {} (R26, R71; it applies after it merges to a full ref)",
            rel.display()
        ));
    }
    let env = EnvSnapshot::default();
    let layout = crate::gitx::RepoLayout::for_hook(&root, &env)?;
    if let Ok(crate::gitx::hooks_path::RepoHooks::Dir(d)) =
        crate::gitx::hooks_path::parse_hooks_path(&layout, &env, None)
        && d != layout.default_hooks_dir()
        && path.starts_with(&d)
    {
        return Some(format!(
            "edit of a repo hook in core.hooksPath {} (R26)",
            d.display()
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
        let cmd = "cd r && git status -m x";
        let input = json!({"command": cmd, "timeout": 1000});
        let out = rewrite(input.as_object().unwrap(), cmd, 540);
        assert_eq!(
            out["command"],
            format!("export TOLLGATE_INLINE_CAP=540; {cmd}")
        );
        assert_eq!(out["timeout"], BASH_TIMEOUT_MS);
        let bg = json!({"command": "git push", "run_in_background": true, "timeout": 900_000});
        let out = rewrite(bg.as_object().unwrap(), "git push", 1200);
        assert_eq!(out["command"], "export TOLLGATE_INLINE_CAP=1200; git push");
        assert_eq!(out["timeout"], 900_000);
    }

    /// Item 12: the guard checks the whole command as received and only
    /// puts its own export in front of that exact text; it never strips a
    /// client prefix (the old rewrite checked only the text after the
    /// first `; ` of a client `TOLLGATE_INLINE_CAP=...; ` prefix).
    #[test]
    fn the_rewrite_never_strips_client_text_item_12() {
        let cmd = "export TOLLGATE_INLINE_CAP=1; git push -m x; ls";
        let out = rewrite(json!({"command": cmd}).as_object().unwrap(), cmd, 540);
        assert_eq!(
            out["command"],
            format!("export TOLLGATE_INLINE_CAP=540; {cmd}")
        );
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
