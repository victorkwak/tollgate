//! Edits of `~/.claude/settings.json` (R3, R23, R95, R96).
//!
//! `install` adds the hook injection to `env` and the guard to
//! `hooks.PreToolUse`, and removes the old `pre-commit-checks.sh` entry.
//! `uninstall` removes exactly what `install` recorded, matched by value.
//! Every other key and the key order stay as they are (`serde_json` with
//! `preserve_order`).

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

/// The marker in every hook command tollgate adds (R95).
pub const MARKER: &str = "tollgate:";

/// The guard matchers (R23).
pub const GUARD_MATCHERS: &[&str] = &["Bash", "Write|Edit|MultiEdit|NotebookEdit"];

/// The guard's PreToolUse timeout in seconds (R23).
pub const GUARD_TIMEOUT_SECS: u64 = 10;

/// The script tollgate replaces (R95c).
pub const OLD_HOOK: &str = "pre-commit-checks.sh";

/// The guard hook command: the installed copy, `guard`, and the marker in
/// a shell comment (Claude Code runs hook commands with a shell).
#[must_use]
pub fn guard_command(binary: &Path) -> String {
    format!(
        "{} guard # {MARKER}guard",
        crate::hook::argv::shell_quote(&binary.to_string_lossy())
    )
}

/// One guard hook object (R23).
#[must_use]
pub fn guard_hook(command: &str) -> Value {
    json!({
        "type": "command",
        "command": command,
        "timeout": GUARD_TIMEOUT_SECS,
        "onFailure": "block",
    })
}

/// A hook `install` removed, kept so `uninstall` can put it back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RemovedHook {
    /// Hook event (`PreToolUse`).
    pub event: String,
    /// The group's matcher, when it had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// The hook object.
    pub hook: Value,
}

/// What `install` changed in the settings, for `uninstall` (R96).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SettingsRecord {
    /// The settings file.
    pub path: std::path::PathBuf,
    /// The backup made before the first edit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<std::path::PathBuf>,
    /// `env` keys tollgate set, with their values.
    pub env: BTreeMap<String, String>,
    /// Guard hook commands tollgate added.
    pub guard_commands: Vec<String>,
    /// Hooks tollgate removed (the old pre-commit script).
    #[serde(default)]
    pub removed: Vec<RemovedHook>,
    /// Containers tollgate created (`env`, `hooks`, `hooks.PreToolUse`).
    #[serde(default)]
    pub created: Vec<String>,
}

fn object<'a>(v: &'a mut Value, what: &str) -> Result<&'a mut Map<String, Value>, String> {
    v.as_object_mut()
        .ok_or_else(|| format!("settings: {what} is not a JSON object"))
}

/// The child object `key` of `parent`, created when missing.
fn child_object<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
    path: &str,
    created: &mut Vec<String>,
) -> Result<&'a mut Map<String, Value>, String> {
    if !parent.contains_key(key) {
        parent.insert(key.to_owned(), Value::Object(Map::new()));
        created.push(path.to_owned());
    }
    parent
        .get_mut(key)
        .and_then(Value::as_object_mut)
        .ok_or_else(|| format!("settings: {path} is not a JSON object"))
}

fn hook_command(hook: &Value) -> Option<&str> {
    hook.get("command").and_then(Value::as_str)
}

/// Applies the install edit to `settings` (R3, R23, R95c). `env` is the
/// injection; `previous` is the record of an earlier install, whose own
/// values may be replaced. Returns the new record.
pub fn apply_install(
    settings: &mut Value,
    path: &Path,
    env: &BTreeMap<String, String>,
    command: &str,
    previous: Option<&SettingsRecord>,
) -> Result<SettingsRecord, String> {
    let mut rec = SettingsRecord {
        path: path.to_owned(),
        backup: previous.and_then(|p| p.backup.clone()),
        env: env.clone(),
        guard_commands: vec![command.to_owned()],
        removed: previous.map(|p| p.removed.clone()).unwrap_or_default(),
        created: previous.map(|p| p.created.clone()).unwrap_or_default(),
    };
    let root = object(settings, "the file")?;
    let env_obj = child_object(root, "env", "env", &mut rec.created)?;
    for (k, v) in env {
        match env_obj.get(k) {
            Some(Value::String(cur)) if cur == v => {}
            Some(cur) => {
                let ours = previous.is_some_and(|p| {
                    p.env
                        .get(k)
                        .is_some_and(|pv| Value::String(pv.clone()) == *cur)
                });
                if !ours {
                    return Err(format!(
                        "settings: env.{k} is already {cur}; tollgate needs {v:?}. Remove it or merge the GIT_CONFIG_* entries by hand, then install again"
                    ));
                }
                env_obj.insert(k.clone(), Value::String(v.clone()));
            }
            None => {
                env_obj.insert(k.clone(), Value::String(v.clone()));
            }
        }
    }
    let hooks = child_object(root, "hooks", "hooks", &mut rec.created)?;
    if !hooks.contains_key("PreToolUse") {
        hooks.insert("PreToolUse".into(), Value::Array(Vec::new()));
        rec.created.push("hooks.PreToolUse".into());
    }
    let groups = hooks
        .get_mut("PreToolUse")
        .and_then(Value::as_array_mut)
        .ok_or("settings: hooks.PreToolUse is not an array")?;
    // Old tollgate entries (another binary path) and the old pre-commit
    // script go; groups left empty by that go too.
    let previous_commands: Vec<&str> = previous
        .map(|p| p.guard_commands.iter().map(String::as_str).collect())
        .unwrap_or_default();
    for g in groups.iter_mut() {
        let matcher = g.get("matcher").and_then(Value::as_str).map(str::to_owned);
        let Some(list) = g.get_mut("hooks").and_then(Value::as_array_mut) else {
            continue;
        };
        let before = list.len();
        let mut kept = Vec::with_capacity(before);
        for h in list.drain(..) {
            let cmd = hook_command(&h).unwrap_or_default();
            if cmd.contains(OLD_HOOK) {
                rec.removed.push(RemovedHook {
                    event: "PreToolUse".into(),
                    matcher: matcher.clone(),
                    hook: h,
                });
            } else if cmd != command
                && (previous_commands.contains(&cmd) || cmd.contains(&format!("# {MARKER}")))
            {
                // An earlier tollgate guard entry.
            } else {
                kept.push(h);
            }
        }
        *list = kept;
        if before > 0 && list.is_empty() {
            g["hooks"] = Value::Null;
        }
    }
    groups.retain(|g| !g.get("hooks").is_some_and(Value::is_null));
    for matcher in GUARD_MATCHERS {
        let present = groups.iter().any(|g| {
            g.get("matcher").and_then(Value::as_str) == Some(*matcher)
                && g.get("hooks")
                    .and_then(Value::as_array)
                    .is_some_and(|l| l.iter().any(|h| hook_command(h) == Some(command)))
        });
        if !present {
            groups.push(json!({
                "matcher": matcher,
                "hooks": [guard_hook(command)],
            }));
        }
    }
    Ok(rec)
}

/// True when the command of a removed hook still names an existing file
/// (its first word, `~` expanded), so putting it back is safe.
fn removed_hook_runnable(hook: &Value, home: &Path) -> bool {
    let Some(cmd) = hook_command(hook) else {
        return false;
    };
    let Some(first) = cmd.split_whitespace().next() else {
        return false;
    };
    let first = first.trim_matches(['"', '\'']);
    let path = if let Some(rest) = first.strip_prefix("~/") {
        home.join(rest)
    } else if let Some(rest) = first.strip_prefix("$HOME/") {
        home.join(rest)
    } else {
        Path::new(first).to_owned()
    };
    path.is_file()
}

/// Applies the uninstall edit (R96): removes the recorded env values and
/// guard commands (by value), containers tollgate created that are now
/// empty, and puts back the hooks install removed when their script still
/// exists. Returns notes for the user.
pub fn apply_uninstall(
    settings: &mut Value,
    rec: &SettingsRecord,
    home: &Path,
) -> Result<Vec<String>, String> {
    let mut notes = Vec::new();
    let root = object(settings, "the file")?;
    if let Some(env) = root.get_mut("env").and_then(Value::as_object_mut) {
        for (k, v) in &rec.env {
            match env.get(k) {
                Some(Value::String(cur)) if cur == v => {
                    env.shift_remove(k);
                }
                Some(cur) => {
                    notes.push(format!("env.{k} is {cur} now (not tollgate's value); kept"))
                }
                None => {}
            }
        }
        if env.is_empty() && rec.created.iter().any(|c| c == "env") {
            root.shift_remove("env");
        }
    }
    if let Some(hooks) = root.get_mut("hooks").and_then(Value::as_object_mut) {
        if let Some(groups) = hooks.get_mut("PreToolUse").and_then(Value::as_array_mut) {
            for g in groups.iter_mut() {
                if let Some(list) = g.get_mut("hooks").and_then(Value::as_array_mut) {
                    let before = list.len();
                    list.retain(|h| {
                        !hook_command(h).is_some_and(|c| rec.guard_commands.iter().any(|g| g == c))
                    });
                    if before > 0 && list.is_empty() {
                        g["hooks"] = Value::Null;
                    }
                }
            }
            groups.retain(|g| !g.get("hooks").is_some_and(Value::is_null));
            for r in rec.removed.iter().filter(|r| r.event == "PreToolUse") {
                let already = groups.iter().any(|g| {
                    g.get("hooks")
                        .and_then(Value::as_array)
                        .is_some_and(|l| l.contains(&r.hook))
                });
                if already {
                    continue;
                }
                if !removed_hook_runnable(&r.hook, home) {
                    notes.push(format!(
                        "not restored (its script is gone): {}",
                        hook_command(&r.hook).unwrap_or("?")
                    ));
                    continue;
                }
                let mut g = Map::new();
                if let Some(m) = &r.matcher {
                    g.insert("matcher".into(), Value::String(m.clone()));
                }
                g.insert("hooks".into(), Value::Array(vec![r.hook.clone()]));
                groups.push(Value::Object(g));
                notes.push(format!(
                    "restored: {}",
                    hook_command(&r.hook).unwrap_or("?")
                ));
            }
            if groups.is_empty() && rec.created.iter().any(|c| c == "hooks.PreToolUse") {
                hooks.shift_remove("PreToolUse");
            }
        }
        if hooks.is_empty() && rec.created.iter().any(|c| c == "hooks") {
            root.shift_remove("hooks");
        }
    }
    Ok(notes)
}

/// Pretty JSON as Claude Code writes it (two-space indent), with a final
/// newline when `like` had one.
#[must_use]
pub fn to_text(v: &Value, like: &str) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into());
    if like.is_empty() || like.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// True when the guard entries and the injection are all present.
#[must_use]
pub fn installed_entries(
    settings: &Value,
    env: &BTreeMap<String, String>,
    command: &str,
) -> (bool, usize) {
    let env_ok = env.iter().all(|(k, v)| {
        settings
            .get("env")
            .and_then(|e| e.get(k))
            .and_then(Value::as_str)
            == Some(v.as_str())
    });
    let guards = settings
        .get("hooks")
        .and_then(|h| h.get("PreToolUse"))
        .and_then(Value::as_array)
        .map_or(0, |groups| {
            GUARD_MATCHERS
                .iter()
                .filter(|m| {
                    groups.iter().any(|g| {
                        g.get("matcher").and_then(Value::as_str) == Some(**m)
                            && g.get("hooks").and_then(Value::as_array).is_some_and(|l| {
                                l.iter().any(|h| {
                                    hook_command(h) == Some(command)
                                        && h.get("onFailure").and_then(Value::as_str)
                                            == Some("block")
                                })
                            })
                    })
                })
                .count()
        });
    (env_ok, guards)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> BTreeMap<String, String> {
        [
            ("GIT_CONFIG_COUNT", "1"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", "/d/tollgate/hooks"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
    }

    const FIXTURE: &str = r#"{
  "model": "opus",
  "env": {
    "FOO": "1"
  },
  "permissions": {
    "allow": ["Bash(ls)"]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "~/.claude/hooks/pre-commit-checks.sh" }
        ]
      },
      {
        "matcher": "Read",
        "hooks": [ { "type": "command", "command": "other" } ]
      }
    ]
  },
  "zzz": true
}
"#;

    #[test]
    fn install_adds_tagged_entries_and_keeps_order_r95() {
        let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
        let cmd = guard_command(Path::new("/d/tollgate/bin/tollgate"));
        assert!(cmd.contains(MARKER));
        let rec = apply_install(&mut v, Path::new("/s.json"), &env(), &cmd, None).unwrap();
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["model", "env", "permissions", "hooks", "zzz"]);
        assert_eq!(v["env"]["FOO"], "1");
        assert_eq!(v["env"]["GIT_CONFIG_VALUE_0"], "/d/tollgate/hooks");
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        // The old script's group is gone; Read stays; two guard groups.
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0]["matcher"], "Read");
        assert_eq!(groups[1]["hooks"][0]["onFailure"], "block");
        assert_eq!(groups[2]["matcher"], "Write|Edit|MultiEdit|NotebookEdit");
        assert_eq!(rec.removed.len(), 1);
        assert!(rec.created.is_empty());
        assert_eq!(installed_entries(&v, &env(), &cmd), (true, 2));
        // A second install changes nothing.
        let before = v.clone();
        apply_install(&mut v, Path::new("/s.json"), &env(), &cmd, Some(&rec)).unwrap();
        assert_eq!(v, before);
    }

    #[test]
    fn uninstall_removes_exactly_what_install_added_r96() {
        let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
        let cmd = guard_command(Path::new("/d/tollgate/bin/tollgate"));
        let rec = apply_install(&mut v, Path::new("/s.json"), &env(), &cmd, None).unwrap();
        // Edits made after install survive.
        v["env"]["LATER"] = json!("x");
        v["hooks"]["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": "command", "command": "added later"}));
        let tmp = tempfile::tempdir().unwrap();
        let notes = apply_uninstall(&mut v, &rec, tmp.path()).unwrap();
        assert!(
            notes.iter().any(|n| n.contains("not restored")),
            "{notes:?}"
        );
        assert_eq!(v["env"], json!({"FOO": "1", "LATER": "x"}));
        let groups = v["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["hooks"].as_array().unwrap().len(), 2);
        let keys: Vec<&String> = v.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["model", "env", "permissions", "hooks", "zzz"]);
    }

    /// The README's rollback text: uninstall itself puts back the entry
    /// install removed when its script still exists (R96).
    #[test]
    fn uninstall_restores_a_removed_hook_whose_script_exists_r96() {
        let mut v: Value = serde_json::from_str(FIXTURE).unwrap();
        let cmd = guard_command(Path::new("/d/tollgate/bin/tollgate"));
        let rec = apply_install(&mut v, Path::new("/s.json"), &env(), &cmd, None).unwrap();
        assert!(!v.to_string().contains("pre-commit-checks.sh"));
        let home = tempfile::tempdir().unwrap();
        let script = home.path().join(".claude/hooks/pre-commit-checks.sh");
        std::fs::create_dir_all(script.parent().unwrap()).unwrap();
        std::fs::write(&script, "#!/bin/sh\n").unwrap();
        let notes = apply_uninstall(&mut v, &rec, home.path()).unwrap();
        assert!(
            notes
                .iter()
                .any(|n| n == "restored: ~/.claude/hooks/pre-commit-checks.sh"),
            "{notes:?}"
        );
        let text = v.to_string();
        assert_eq!(text.matches("pre-commit-checks.sh").count(), 1, "{v:#}");
        assert!(!text.contains(MARKER), "{v:#}");
    }

    #[test]
    fn install_into_empty_settings_and_back_r96() {
        let mut v = json!({});
        let cmd = guard_command(Path::new("/d/b"));
        let rec = apply_install(&mut v, Path::new("/s.json"), &env(), &cmd, None).unwrap();
        assert_eq!(rec.created, ["env", "hooks", "hooks.PreToolUse"]);
        apply_uninstall(&mut v, &rec, Path::new("/nonexistent")).unwrap();
        assert_eq!(v, json!({}));
    }

    #[test]
    fn a_foreign_injection_is_refused_r3() {
        let mut v = json!({"env": {"GIT_CONFIG_COUNT": "2"}});
        let err = apply_install(&mut v, Path::new("/s.json"), &env(), "c", None).unwrap_err();
        assert!(err.contains("GIT_CONFIG_COUNT"), "{err}");
    }
}
