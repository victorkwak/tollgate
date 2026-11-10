//! The guard's verdicts (R25 deny, R26 ask, R28 rewrite trigger) and the
//! context they need.
//!
//! The guard stops a careless agent, not a hostile one. Bash calls go
//! through the open grammar in [`super::walk`]: the command is parsed
//! ([`super::shell`]), and a rule fires only where bash, git or an
//! ordinary tool reads the word that the rule is about. Every other
//! command is allowed. There are no raw-text rules: messages, grep
//! patterns and file contents that mention `--no-verify` or
//! `GIT_CONFIG_COUNT` stay allowed. Text that names git, tollgate or
//! `.claude` and that the walker cannot read (no parse, code made at run
//! time) asks under the rule id `unclassified`.
//!
//! Each rule has an id ([`Reason::rule`]) that the metrics log records.
//!
//! Write/Edit tool calls get the path rules ([`file_ruling`]); the walker
//! applies [`write_ruling`] to the files a Bash command writes.

use std::path::{Path, PathBuf};

use globset::GlobSet;

use super::shell;
use super::walk;

/// Why a rule fired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// The rule's id, for the metrics log (`no-verify`, `state-dir-write`).
    pub rule: &'static str,
    /// One line for the agent or the person: what was found and what to
    /// do.
    pub why: String,
}

/// The guard's verdict on one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ruling {
    /// No rule matched.
    Allow,
    /// `permissionDecision: "ask"` with this reason (R26).
    Ask(Reason),
    /// Exit 2 with this reason (R25).
    Deny(Reason),
}

impl Ruling {
    #[must_use]
    pub fn deny(rule: &'static str, why: impl Into<String>) -> Self {
        Self::Deny(Reason {
            rule,
            why: why.into(),
        })
    }

    #[must_use]
    pub fn ask(rule: &'static str, why: impl Into<String>) -> Self {
        Self::Ask(Reason {
            rule,
            why: why.into(),
        })
    }

    /// The reason of an ask or a deny.
    #[must_use]
    pub fn reason(&self) -> Option<&Reason> {
        match self {
            Self::Allow => None,
            Self::Ask(r) | Self::Deny(r) => Some(r),
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Ask(_) => 1,
            Self::Deny(_) => 2,
        }
    }

    /// The stronger of two rulings (deny > ask > allow; the first wins a
    /// tie).
    #[must_use]
    pub fn max(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

/// Paths and patterns the rules need.
#[derive(Debug, Clone)]
pub struct Context {
    /// The tool call's cwd, for relative paths.
    pub cwd: PathBuf,
    /// `$HOME`.
    pub home: PathBuf,
    /// Variables of the session environment the rules may expand in paths
    /// (`HOME`, `XDG_*_HOME`, `TMPDIR`, `CDPATH`, ...).
    pub vars: Vec<(String, String)>,
    /// tollgate's state, data and config dirs (R25: no writes).
    pub protected: Vec<PathBuf>,
    /// The host config (R26: ask, not deny).
    pub host_config: PathBuf,
    /// `tiers.full_refs`, matched case-insensitively (R27).
    pub full_refs: GlobSet,
    /// Names the tollgate binary goes by (PATH name, installed copy).
    pub tollgate_names: Vec<String>,
    /// The `TOLLGATE_INLINE_CAP` the guard exports for this call: a
    /// client value may only lower it.
    pub inline_cap: u64,
}

impl Context {
    /// The session value of `name`, when the rules may use it.
    #[must_use]
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// The verdict on a Bash command and whether it needs the R28 rewrite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    pub ruling: Ruling,
    /// It runs a git command that can wait in a gate hook, or `tollgate
    /// check|wait|merge` (R28).
    pub long_timeout: bool,
}

/// R25/R26/R28 for a Bash command.
#[must_use]
pub fn assess(ctx: &Context, command: &str) -> Assessment {
    walk::assess(ctx, command)
}

/// R25/R26 for a Bash command.
#[must_use]
pub fn bash_ruling(ctx: &Context, command: &str) -> Ruling {
    assess(ctx, command).ruling
}

/// R28: true when the command runs a git command that can wait in a gate
/// hook, or `tollgate check|wait|merge`.
#[must_use]
pub fn needs_long_timeout(ctx: &Context, command: &str) -> bool {
    assess(ctx, command).long_timeout
}

/// The last path component of `word`.
#[must_use]
pub fn basename(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// True when `word` names the tollgate binary: the PATH name, an installed
/// copy, or any path whose last component is `tollgate`.
#[must_use]
pub fn is_tollgate(ctx: &Context, word: &str) -> bool {
    if basename(word).eq_ignore_ascii_case("tollgate") {
        return true;
    }
    let p = crate::guard::paths::lexical(&ctx.cwd, Path::new(word));
    ctx.tollgate_names.iter().any(|n| Path::new(n) == p)
}

/// L8: a single simple command `tollgate install|uninstall|doctor|status`
/// (by PATH name or the installed copy) with literal words, allowed while
/// the gate is not armed so it can be repaired from a session.
#[must_use]
pub fn is_repair_command(ctx: &Context, command: &str) -> bool {
    if command.contains(['`', '$', ';', '&', '|', '\n', '<', '>', '(']) {
        return false;
    }
    let Ok(script) = shell::parse(command) else {
        return false;
    };
    let [ao] = script.items.as_slice() else {
        return false;
    };
    if !ao.rest.is_empty() || ao.background || ao.first.negate {
        return false;
    }
    let [cmd] = ao.first.cmds.as_slice() else {
        return false;
    };
    let shell::Kind::Simple(sc) = &cmd.kind else {
        return false;
    };
    if !sc.assigns.is_empty() || !cmd.redirs.is_empty() {
        return false;
    }
    let words: Option<Vec<String>> = sc
        .words
        .iter()
        .map(|w| w.literal_home(&ctx.home.to_string_lossy()))
        .collect();
    let Some(words) = words else {
        return false;
    };
    words.first().is_some_and(|w| is_tollgate(ctx, w))
        && words
            .get(1)
            .is_some_and(|s| matches!(s.as_str(), "install" | "uninstall" | "doctor" | "status"))
}

/// The path rules for a file that an ordinary tool of a Bash command
/// writes (M3): a redirection, `cp`, `mv`, `rm`, `sed -i`, `tee` and the
/// like. `spelled` is absolute, with `.` and `..` applied; `removal` is
/// true when the tool removes the path or reaches what is under it.
#[must_use]
pub fn write_ruling(ctx: &Context, spelled: &Path, removal: bool, how: &str) -> Ruling {
    use crate::guard::paths;
    let text = paths::lower(spelled);
    if text.starts_with("/dev/") || text.starts_with("/proc/") {
        return Ruling::Allow;
    }
    // The path as spelled, then with its symlinks resolved: a link into
    // tollgate's dirs, `.git` or `.claude` does not hide the target.
    let resolved = paths::canon(spelled);
    // git's global config files are looked up only for a path that can
    // be one of them.
    let near = [text.as_str(), paths::lower(&resolved).as_str()]
        .iter()
        .any(|t| t.contains("git"));
    let mut seen: Option<&Path> = None;
    for p in [spelled, resolved.as_path()] {
        if seen == Some(p) {
            break;
        }
        seen = Some(p);
        if paths::lower(p) == paths::lower(&ctx.host_config) {
            return Ruling::ask(
                "host-config-edit",
                format!(
                    "{how} writes the tollgate host config {} (R26)",
                    p.display()
                ),
            );
        }
        if let Some(dir) = paths::tollgate_dir(ctx, p, removal) {
            return Ruling::deny(
                "state-dir-write",
                format!(
                    "{how} writes {} in tollgate's dir {}: records, jobs and the installed hooks are only written by tollgate (R25)",
                    p.display(),
                    dir.display()
                ),
            );
        }
        if paths::claude_settings(ctx, p) {
            return Ruling::ask(
                "claude-settings-edit",
                format!(
                    "{how} changes Claude Code settings at {}, which register the guard and the hook injection; a person decides (R26)",
                    p.display()
                ),
            );
        }
        let comps: Vec<String> = p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
            .collect();
        let dot_git = comps.iter().position(|c| c == ".git");
        if let Some(what) = paths::git_internal(p) {
            return Ruling::ask(
                "git-dir-write",
                format!(
                    "{how} writes {what} of a repo ({}): it can move refs, remotes or hooks without a check (R26)",
                    p.display()
                ),
            );
        }
        if let Some(k) = dot_git {
            let under = &comps[k + 1..];
            if under.is_empty() && removal || under == ["head"] {
                return Ruling::ask(
                    "git-dir-write",
                    format!(
                        "{how} removes or rewrites {} of a repo: refs and hooks go with it (R26)",
                        p.display()
                    ),
                );
            }
            if removal && under.last().is_some_and(|n| n.ends_with(".lock")) {
                return Ruling::ask(
                    "git-lock-file",
                    format!(
                        "{how} removes the git lock file {}: another git process or a gate job can hold it. Check first: `tollgate status` in the repo lists running gate jobs, and `tollgate doctor --repo <repo>` reports the lock stale when no git process works there (R26, R39)",
                        p.display()
                    ),
                );
            }
        }
        if comps.iter().any(|c| c == ".githooks") {
            return Ruling::ask(
                "repo-hook-edit",
                format!("{how} writes the repo hook {} (R26)", p.display()),
            );
        }
        if near && let Some(f) = paths::git_global_config(ctx, p) {
            return Ruling::ask(
                "git-global-config-edit",
                format!(
                    "{how} writes git's config file {}, whose program keys every git command runs (R26)",
                    f.display()
                ),
            );
        }
    }
    if let Some((rule, why)) = super::repo_rules(spelled) {
        return Ruling::ask(rule, why);
    }
    Ruling::Allow
}

/// The path rules (R25, R26) for Write/Edit/MultiEdit/NotebookEdit: deny
/// under tollgate's dirs; ask for the host config, Claude Code settings,
/// `.git/`, `.githooks/`, git's global config, a repo's `core.hooksPath`
/// dir and a policy file. The path is checked as spelled and with its
/// symlinks resolved.
#[must_use]
pub fn file_ruling(ctx: &Context, file: &str) -> Ruling {
    use crate::guard::paths;
    let spelled = paths::lexical(&ctx.cwd, Path::new(&expand_home(ctx, file)));
    let resolved = paths::canon(&spelled);
    let mut out = Ruling::Allow;
    for p in [&resolved, &spelled] {
        out = out.max(file_rule(ctx, p));
        if matches!(out, Ruling::Deny(_)) || spelled == resolved {
            break;
        }
    }
    out
}

fn file_rule(ctx: &Context, p: &Path) -> Ruling {
    use crate::guard::paths;
    if paths::lower(p) == paths::lower(&ctx.host_config) {
        return Ruling::ask(
            "host-config-edit",
            format!("edit of the tollgate host config {} (R26)", p.display()),
        );
    }
    if let Some(dir) = paths::tollgate_dir(ctx, p, false) {
        return Ruling::deny(
            "state-dir-write",
            format!("write under tollgate's dir {} (R25, R26)", dir.display()),
        );
    }
    if paths::claude_settings(ctx, p) {
        return Ruling::ask(
            "claude-settings-edit",
            format!("edit of Claude Code settings {} (R26)", p.display()),
        );
    }
    let in_dir = |d: &str| {
        p.components()
            .any(|c| c.as_os_str().to_string_lossy().eq_ignore_ascii_case(d))
    };
    if in_dir(".git") {
        return Ruling::ask(
            "git-dir-write",
            format!("write under .git/: {} (R26)", p.display()),
        );
    }
    if in_dir(".githooks") {
        return Ruling::ask(
            "repo-hook-edit",
            format!("edit of a repo hook {} (R26)", p.display()),
        );
    }
    if let Some(f) = paths::git_global_config(ctx, p) {
        return Ruling::ask(
            "git-global-config-edit",
            format!(
                "edit of git's config file {}, which every git command reads (R26)",
                f.display()
            ),
        );
    }
    if let Some((rule, why)) = super::repo_rules(p) {
        return Ruling::ask(rule, why);
    }
    Ruling::Allow
}

/// `~` and `~/...` as the session's home.
fn expand_home(ctx: &Context, file: &str) -> String {
    if file == "~" || file.starts_with("~/") {
        return format!("{}{}", ctx.home.display(), &file[1..]);
    }
    file.to_owned()
}

#[cfg(test)]
mod tests;
