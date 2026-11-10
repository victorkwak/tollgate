//! Agent CLIs (G2, review "nested agent without hooks"). An agent runs
//! its own tool calls, and only the PreToolUse guard stands between those
//! and a git command with the hook injection dropped. Claude Code loads
//! the guard from the user settings, so `claude` runs only with options
//! from a closed list that keeps them and their hooks, loads no code that
//! runs outside the guard and keeps a person on the questions the guard
//! asks. `codex`, `gemini` and the other agent CLIs never load the guard:
//! they run only to print their version or help.

/// What the guard says about one agent command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    /// A person decides (R26).
    Ask(String),
    Deny(String),
}

/// The agent CLI `base` (a basename) names: `claude`, `codex`, `gemini`
/// or another one. Package names as runners spell them count
/// (`@anthropic-ai/claude-code@2.1.0` has the basename
/// `claude-code@2.1.0`).
#[must_use]
pub fn agent_of(base: &str) -> Option<&'static str> {
    let name = match base.split_once('@') {
        Some((n, _)) if !n.is_empty() => n,
        _ => base,
    };
    match name {
        "claude" | "claude-code" => Some("claude"),
        "codex" => Some("codex"),
        "gemini" | "gemini-cli" => Some("gemini"),
        _ => OTHERS.iter().find(|n| **n == name).copied(),
    }
}

/// Agent CLIs other than claude, codex and gemini (they never load the
/// guard either).
const OTHERS: &[&str] = &[
    "opencode",
    "aider",
    "cursor-agent",
    "qwen",
    "crush",
    "amp",
    "copilot",
    "droid",
    "cline",
    "kiro-cli",
    "auggie",
];

/// The basename of a file in Claude Code's own install dir
/// (`.../claude/versions/<version>`), which a link under any name runs.
#[must_use]
pub fn installed_claude(real: &std::path::Path) -> bool {
    real.parent().is_some_and(|d| {
        d.file_name().is_some_and(|n| n == "versions")
            && d.parent()
                .and_then(|p| p.file_name())
                .is_some_and(|n| n == "claude")
    })
}

/// The verdict on `agent` run with `words` (its arguments; `None` is a
/// word bash builds at run time).
#[must_use]
pub fn check(agent: &str, words: &[Option<String>]) -> Verdict {
    if agent == "claude" {
        return claude(words);
    }
    match words {
        [Some(w)] if PRINTS.contains(&w.as_str()) => Verdict::Allow,
        _ => Verdict::Deny(format!(
            "{agent} runs an agent that never loads tollgate's guard, so its commands may drop the hook injection before git; run it at your own terminal (G2)"
        )),
    }
}

/// The verdict on `agent` named in the words of a program the guard does
/// not know, which may run it with `words` (item 21/20). Those words may
/// be that program's own (`notesmd-cli search-content claude
/// --no-interactive`), so only the ones that drop the guard deny here.
#[must_use]
pub fn check_named(agent: &str, words: &[Option<String>]) -> Verdict {
    if agent == "claude" {
        return claude_off(words).map_or(Verdict::Allow, Verdict::Deny);
    }
    let runs = words
        .iter()
        .flatten()
        .find(|w| RUN_WORDS.contains(&w.split('=').next().unwrap_or(w)));
    match runs {
        Some(w) => Verdict::Deny(format!(
            "{agent} `{w}` runs an agent that never loads tollgate's guard, so its commands may drop the hook injection before git; run it at your own terminal (G2)"
        )),
        None => Verdict::Allow,
    }
}

/// What prints a version or help and runs nothing.
const PRINTS: &[&str] = &["--version", "-V", "-v", "--help", "-h", "help"];

/// Words of the other agent CLIs that start an agent or run a command
/// (subcommands, prompt options, approval and sandbox bypasses).
const RUN_WORDS: &[&str] = &[
    "exec",
    "e",
    "run",
    "review",
    "resume",
    "fork",
    "apply",
    "sandbox",
    "debug",
    "cloud",
    "app-server",
    "exec-server",
    "mcp-server",
    "queue",
    "serve",
    "chat",
    "-p",
    "--prompt",
    "-i",
    "--prompt-interactive",
    "-m",
    "--message",
    "-y",
    "--yes",
    "--yes-always",
    "--yolo",
    "--full-auto",
    "--approval-mode",
    "--dangerously-bypass-approvals-and-sandbox",
    "-c",
    "--config",
    "-e",
    "--extensions",
];

/// How many words a Claude Code option takes (commander rules: a
/// required value is the next word whatever it is; an optional one is
/// the next word when it does not start with `-`; a variadic one takes
/// the next word, then every word up to one that starts with `-`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arity {
    Flag,
    Value,
    Optional,
    Many,
}

/// Claude Code options (2.1.317, `claude --help`) that keep the user
/// settings, their hooks and a person on the guard's questions. Any other
/// option denies: the list is closed, so a new or hidden option is not
/// a way around it.
const CLAUDE_LONG: &[(&str, Arity)] = &[
    ("print", Arity::Flag),
    ("continue", Arity::Flag),
    ("verbose", Arity::Flag),
    ("include-partial-messages", Arity::Flag),
    ("include-hook-events", Arity::Flag),
    ("forward-subagent-text", Arity::Flag),
    ("no-session-persistence", Arity::Flag),
    ("fork-session", Arity::Flag),
    ("chrome", Arity::Flag),
    ("no-chrome", Arity::Flag),
    ("ide", Arity::Flag),
    ("ax-screen-reader", Arity::Flag),
    ("exclude-dynamic-system-prompt-sections", Arity::Flag),
    ("brief", Arity::Flag),
    ("strict-mcp-config", Arity::Flag),
    ("disable-slash-commands", Arity::Flag),
    ("help", Arity::Flag),
    ("version", Arity::Flag),
    ("bg", Arity::Flag),
    ("background", Arity::Flag),
    ("model", Arity::Value),
    ("fallback-model", Arity::Value),
    ("effort", Arity::Value),
    ("output-format", Arity::Value),
    ("input-format", Arity::Value),
    ("json-schema", Arity::Value),
    ("max-budget-usd", Arity::Value),
    ("max-turns", Arity::Value),
    ("append-system-prompt", Arity::Value),
    ("system-prompt", Arity::Value),
    ("append-system-prompt-file", Arity::Value),
    ("system-prompt-file", Arity::Value),
    ("name", Arity::Value),
    ("session-id", Arity::Value),
    ("autocompact", Arity::Value),
    ("system-prompt-snapshot", Arity::Value),
    ("permission-prompts", Arity::Value),
    ("permission-mode", Arity::Value),
    ("setting-sources", Arity::Value),
    ("resume", Arity::Optional),
    ("worktree", Arity::Optional),
    ("debug", Arity::Optional),
    ("prompt-suggestions", Arity::Optional),
    ("from-pr", Arity::Optional),
    ("allowedTools", Arity::Many),
    ("allowed-tools", Arity::Many),
    ("disallowedTools", Arity::Many),
    ("disallowed-tools", Arity::Many),
    ("tools", Arity::Many),
    ("betas", Arity::Many),
];

const CLAUDE_SHORT: &[(char, Arity)] = &[
    ('p', Arity::Flag),
    ('c', Arity::Flag),
    ('h', Arity::Flag),
    ('v', Arity::Flag),
    ('n', Arity::Value),
    ('d', Arity::Optional),
    ('r', Arity::Optional),
    ('w', Arity::Optional),
];

/// Claude Code options that drop the guard, and why. They deny wherever
/// they appear, also after a subcommand.
const CLAUDE_OFF: &[(&str, &str)] = &[
    (
        "bare",
        "skips the hooks in settings, tollgate's guard among them",
    ),
    ("safe-mode", "turns hooks off, tollgate's guard among them"),
    (
        "restricted",
        "ignores the user settings, where tollgate's guard is",
    ),
    (
        "settings",
        "loads settings that can turn hooks off, set the environment or run commands outside the guard",
    ),
    (
        "mcp-config",
        "starts MCP servers, programs that run outside the guard",
    ),
    (
        "plugin-dir",
        "loads plugins whose hooks and servers run outside the guard",
    ),
    (
        "plugin-url",
        "loads plugins whose hooks and servers run outside the guard",
    ),
    (
        "agents",
        "loads agent definitions with their own hooks and permission modes",
    ),
    (
        "agent",
        "runs an agent definition with its own hooks and permission mode",
    ),
    (
        "add-dir",
        "loads files from more dirs, and the guard does not know what they configure",
    ),
    (
        "dangerously-skip-permissions",
        "skips the permission prompts, so no person answers the questions the guard asks",
    ),
    (
        "allow-dangerously-skip-permissions",
        "lets the session skip the permission prompts, so no person answers the questions the guard asks",
    ),
    (
        "permission-prompt-tool",
        "lets a tool, not a person, answer the questions the guard asks",
    ),
    ("debug-file", "writes a file the guard does not check"),
];

const SUBCOMMANDS: &[&str] = &[
    "agents",
    "attach",
    "auth",
    "auto-mode",
    "doctor",
    "gateway",
    "help",
    "import",
    "install",
    "logs",
    "mcp",
    "plugin",
    "plugins",
    "purge",
    "respawn",
    "rm",
    "setup-token",
    "stop",
    "kill",
    "ultrareview",
    "update",
    "upgrade",
];

fn deny(why: &str) -> Verdict {
    Verdict::Deny(format!("claude {why}; run it at your own terminal (G2)"))
}

/// A word bash builds where Claude Code reads options (G2).
fn built() -> Verdict {
    Verdict::Deny(
        "claude with a word bash builds at run time where it reads options, which may be one that drops tollgate's guard: put `--` before a prompt bash builds, or give the prompt on stdin (G2)"
            .into(),
    )
}

/// Why a value of `opt` drops the guard, if it does (`None`: a value bash
/// builds at run time).
fn bad_value(opt: &str, v: Option<&str>) -> Option<String> {
    let known = |ok: &[&str]| match v {
        Some(v) if ok.contains(&v) => None,
        Some(v) => Some(format!("`--{opt} {v}`")),
        None => Some(format!("`--{opt}` with a value bash builds at run time")),
    };
    match opt {
        "permission-mode" => known(&["default", "acceptEdits", "auto", "manual", "dontAsk", "plan"])
            .map(|o| format!("{o} may skip the permission prompts, so no person answers the questions the guard asks")),
        "input-format" => known(&["text"]).map(|o| {
            format!("{o} lets stdin answer the questions the guard asks and change the session's mode")
        }),
        "setting-sources" => match v {
            Some(v) if v.split(',').any(|s| s.trim() == "user") => None,
            Some(v) => Some(format!(
                "`--setting-sources {v}` skips the user settings, where tollgate's guard is"
            )),
            None => Some(
                "`--setting-sources` with a value bash builds at run time may skip the user settings, where tollgate's guard is"
                    .into(),
            ),
        },
        _ => None,
    }
}

fn claude(words: &[Option<String>]) -> Verdict {
    let mut i = 0;
    let mut operand = false;
    while i < words.len() {
        let Some(w) = words[i].as_deref() else {
            return built();
        };
        i += 1;
        if w == "--" {
            break;
        }
        if let Some(long) = w.strip_prefix("--") {
            let (n, glued) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (long, None),
            };
            if let Some((_, why)) = CLAUDE_OFF.iter().find(|(o, _)| *o == n) {
                return deny(&format!("`--{n}` {why}"));
            }
            let Some(&(_, arity)) = CLAUDE_LONG.iter().find(|(o, _)| *o == n) else {
                return deny(&format!(
                    "`--{n}`: an option the guard does not know may drop tollgate's guard"
                ));
            };
            let value = match glued {
                Some(v) => Some(Some(v.to_owned())),
                None => match take(words, &mut i, arity) {
                    Ok(v) => v,
                    Err(()) => return built(),
                },
            };
            if let Some(v) = value
                && let Some(why) = bad_value(n, v.as_deref())
            {
                return deny(&why);
            }
            continue;
        }
        if let Some(cluster) = w.strip_prefix('-').filter(|c| !c.is_empty()) {
            for (k, c) in cluster.char_indices() {
                let Some(&(_, arity)) = CLAUDE_SHORT.iter().find(|(o, _)| *o == c) else {
                    return deny(&format!(
                        "`-{c}`: an option the guard does not know may drop tollgate's guard"
                    ));
                };
                if arity == Arity::Flag {
                    continue;
                }
                if cluster[k + c.len_utf8()..].is_empty() && take(words, &mut i, arity).is_err() {
                    return built();
                }
                break;
            }
            continue;
        }
        // The first operand is a subcommand when it names one; any other
        // operand is the prompt.
        if !operand {
            operand = true;
            if SUBCOMMANDS.contains(&w) {
                return claude_sub(w, &words[i..]);
            }
        }
    }
    Verdict::Allow
}

/// Consumes the value words of an option of `arity` given without `=`.
/// `Ok(Some(v))`: the value word; `Err`: a word bash builds where
/// commander may read an option.
#[allow(clippy::option_option)]
fn take(
    words: &[Option<String>],
    i: &mut usize,
    arity: Arity,
) -> Result<Option<Option<String>>, ()> {
    match arity {
        Arity::Flag => Ok(None),
        Arity::Value => {
            let v = words.get(*i).cloned();
            *i += 1;
            Ok(v)
        }
        Arity::Optional => match words.get(*i) {
            Some(Some(v)) if !v.starts_with('-') => {
                *i += 1;
                Ok(Some(Some(v.clone())))
            }
            Some(None) => Err(()),
            _ => Ok(None),
        },
        Arity::Many => {
            let first = words.get(*i).cloned();
            *i += 1;
            loop {
                match words.get(*i) {
                    Some(Some(v)) if !v.starts_with('-') => *i += 1,
                    Some(None) => return Err(()),
                    _ => return Ok(first),
                }
            }
        }
    }
}

/// The options in `words` that drop the guard wherever they appear.
fn claude_off(words: &[Option<String>]) -> Option<String> {
    for (k, w) in words.iter().enumerate() {
        let Some(w) = w else { continue };
        if w == "--" {
            break;
        }
        let Some(long) = w.strip_prefix("--") else {
            continue;
        };
        let (n, glued) = match long.split_once('=') {
            Some((n, v)) => (n, Some(v.to_owned())),
            None => (long, words.get(k + 1).cloned().flatten()),
        };
        if let Some((_, why)) = CLAUDE_OFF.iter().find(|(o, _)| *o == n) {
            return Some(format!(
                "claude `--{n}` {why}; run it at your own terminal (G2)"
            ));
        }
        if let Some(why) = bad_value(n, glued.as_deref()) {
            return Some(format!("claude {why}; run it at your own terminal (G2)"));
        }
    }
    None
}

fn claude_sub(sub: &str, rest: &[Option<String>]) -> Verdict {
    if let Some(why) = claude_off(rest) {
        return Verdict::Deny(why);
    }
    // The first operand after the subcommand (`mcp add`, `plugin list`).
    let op = |words: &[Option<String>]| -> Result<Option<(String, usize)>, ()> {
        for (k, w) in words.iter().enumerate() {
            match w {
                None => return Err(()),
                Some(w) if w.starts_with('-') => {}
                Some(w) => return Ok(Some((w.clone(), k))),
            }
        }
        Ok(None)
    };
    let built = || {
        Verdict::Deny(format!(
            "claude {sub} with a word bash builds at run time where it reads its subcommand; write the subcommand literally (G2)"
        ))
    };
    let installs = |what: &str| {
        Verdict::Ask(format!(
            "claude {what} installs code (hooks, MCP servers) that Claude Code runs outside tollgate's guard in later sessions; a person decides (G2, R26)"
        ))
    };
    match sub {
        // It dispatches sessions: only its listing runs here.
        "agents" => {
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_deref() {
                    Some("--json" | "--all" | "-h" | "--help") => {}
                    Some("--cwd") => i += 1,
                    Some(w) if w.starts_with("--cwd=") => {}
                    _ => {
                        return deny(
                            "agents dispatches sessions with options the guard does not check; only `claude agents --json` runs here",
                        );
                    }
                }
                i += 1;
            }
            Verdict::Allow
        }
        "mcp" => match op(rest) {
            Err(()) => built(),
            Ok(Some((o, _)))
                if matches!(o.as_str(), "add" | "add-json" | "add-from-claude-desktop") =>
            {
                Verdict::Ask(format!(
                    "claude mcp {o} adds an MCP server, a program Claude Code runs outside tollgate's guard; a person decides (G2, R26)"
                ))
            }
            Ok(Some((o, _))) if o == "serve" => deny(
                "mcp serve runs Claude Code's tools for an MCP client, and the guard does not see those calls",
            ),
            Ok(_) => Verdict::Allow,
        },
        "plugin" | "plugins" => match op(rest) {
            Err(()) => built(),
            Ok(Some((o, _)))
                if matches!(
                    o.as_str(),
                    "install" | "i" | "enable" | "update" | "configure"
                ) =>
            {
                installs(&format!("plugin {o}"))
            }
            Ok(Some((o, k))) if o == "marketplace" => match op(&rest[k + 1..]) {
                Err(()) => built(),
                Ok(Some((m, _))) if matches!(m.as_str(), "add" | "update") => {
                    installs(&format!("plugin marketplace {m}"))
                }
                Ok(_) => Verdict::Allow,
            },
            Ok(Some((o, _))) if matches!(o.as_str(), "eval" | "test") => deny(&format!(
                "plugin {o} runs plugin code or sessions the guard does not check"
            )),
            Ok(_) => Verdict::Allow,
        },
        "import" => installs("import"),
        _ => Verdict::Allow,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<Option<String>> {
        s.split_whitespace()
            .map(|w| (w != "$X").then(|| w.to_owned()))
            .collect()
    }

    fn denied(a: &str, s: &str) -> bool {
        matches!(check(a, &words(s)), Verdict::Deny(_))
    }

    #[test]
    fn claude_options_are_a_closed_list() {
        for s in [
            "--bare -p x",
            "--safe-mode -p x",
            "-p x --restricted",
            "-p --setting-sources project x",
            "-p --setting-sources=local,project x",
            "-p --setting-sources $X x",
            "-p --settings {} x",
            "-p --permission-mode bypassPermissions x",
            "-p --permission-mode=bypassPermissions x",
            "-p --permission-mode $X x",
            "-p --input-format stream-json",
            "-p --zz x",
            "-pz x",
            "-p $X",
            "--allowedTools Bash $X -p x",
            "--resume $X -p x",
            "-r $X -p x",
            "--model haiku mcp --bare",
            "mcp list --mcp-config {}",
            "agents --settings {}",
            "agents --model x",
            "plugin eval x",
            "mcp serve",
            "plugin $X",
        ] {
            assert!(denied("claude", s), "{s}");
        }
        for s in [
            "--version",
            "-p x --model haiku --max-turns 1",
            "-p -- $X",
            "-p --model $X x",
            "-p --setting-sources user,project x",
            "-p --permission-mode plan x",
            "--allowedTools Bash Edit -p x",
            // A variadic option takes the next word, whatever it is.
            "--tools --bare -p x",
            "-c -p x",
            "-r abc -p x",
            "-nname -p x",
            "-d -p x",
            "--debug=hooks -p x",
            "mcp list",
            "mcp get serena",
            "plugin validate ./plugin",
            "plugin marketplace list",
            "agents --json --cwd /x",
            "x --model haiku",
        ] {
            assert_eq!(check("claude", &words(s)), Verdict::Allow, "{s}");
        }
        for s in [
            "plugin install x",
            "plugin i x",
            "plugin marketplace add ./m",
            "mcp add x -- sh",
            "import codex",
        ] {
            assert!(matches!(check("claude", &words(s)), Verdict::Ask(_)), "{s}");
        }
    }

    #[test]
    fn other_agents_only_print() {
        for (a, s) in [
            ("codex", "exec x"),
            ("codex", "x"),
            ("gemini", "-p x"),
            ("aider", ""),
        ] {
            assert!(denied(a, s), "{a} {s}");
        }
        for (a, s) in [
            ("codex", "--version"),
            ("gemini", "--help"),
            ("codex", "help"),
        ] {
            assert_eq!(check(a, &words(s)), Verdict::Allow, "{a} {s}");
        }
    }

    #[test]
    fn named_agents_deny_only_what_drops_the_guard() {
        assert_eq!(
            check_named("claude", &words("--no-interactive")),
            Verdict::Allow
        );
        assert_eq!(
            check_named("codex", &words("--no-interactive")),
            Verdict::Allow
        );
        assert!(matches!(
            check_named("claude", &words("--bare -p x")),
            Verdict::Deny(_)
        ));
        assert!(matches!(
            check_named("codex", &words("exec x")),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn names() {
        assert_eq!(agent_of("claude"), Some("claude"));
        assert_eq!(agent_of("claude-code@2.1.0"), Some("claude"));
        assert_eq!(agent_of("codex@0.5"), Some("codex"));
        assert_eq!(agent_of("gemini-cli"), Some("gemini"));
        assert_eq!(agent_of("claude.md"), None);
        assert_eq!(agent_of("@x"), None);
        assert!(installed_claude(std::path::Path::new(
            "/h/.local/share/claude/versions/2.1.317"
        )));
        assert!(!installed_claude(std::path::Path::new("/usr/bin/true")));
    }
}
