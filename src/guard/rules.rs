//! The guard's verdicts (R25 deny, R26 ask, R28 rewrite trigger) and the
//! context they need.
//!
//! Bash calls go through the closed grammar in [`super::walk`] (G1-G8):
//! the command is parsed ([`super::shell`]) and every simple command must
//! fit an allowed shape. Anything outside the grammar is denied with a
//! message that shows the shape to use. There are no raw-text rules: a
//! name or a flag counts only in the position where bash and git read it,
//! so messages, grep patterns and file contents that mention
//! `--no-verify` or `GIT_CONFIG_COUNT` stay allowed (item 42).
//!
//! Write/Edit tool calls get the R25/R26 path rules ([`file_ruling`]).

use std::path::{Path, PathBuf};

use globset::GlobSet;

use super::shell;
use super::walk;

/// The guard's verdict on one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ruling {
    /// No rule matched.
    Allow,
    /// `permissionDecision: "ask"` with this reason (R26).
    Ask(String),
    /// Exit 2 with this reason (R25).
    Deny(String),
}

impl Ruling {
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
    /// The host config (R26: ask, not deny, for Write/Edit).
    pub host_config: PathBuf,
    /// `tiers.full_refs`, matched case-insensitively (R27).
    pub full_refs: GlobSet,
    /// Names the tollgate binary goes by (PATH name, installed copy).
    pub tollgate_names: Vec<String>,
    /// The `TOLLGATE_INLINE_CAP` the guard exports for this call (G6): a
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

/// R25/R26/R28 for a Bash command (G1-G8).
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

/// R26, R25 and G7 for Write/Edit/MultiEdit/NotebookEdit.
#[must_use]
pub fn file_ruling(ctx: &Context, file: &str) -> Ruling {
    use crate::guard::paths;
    let p = paths::canon(&paths::lexical(
        &ctx.cwd,
        Path::new(&expand_home(ctx, file)),
    ));
    if paths::lower(&p) == paths::lower(&ctx.host_config) {
        return Ruling::Ask(format!(
            "edit of the tollgate host config {} (R26)",
            p.display()
        ));
    }
    if let Some(dir) = paths::tollgate_dir(ctx, &p, false) {
        return Ruling::Deny(format!(
            "write under tollgate's dir {} (R25, R26)",
            dir.display()
        ));
    }
    if let Some(what) = paths::git_internal(&p) {
        return Ruling::Deny(format!(
            "write into {what} of a repo ({}): it moves refs, remotes or hooks without a check (G7)",
            p.display()
        ));
    }
    let comps: Vec<String> = p
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    let file_name = comps.last().cloned().unwrap_or_default();
    if comps.len() >= 2
        && comps[comps.len() - 2] == ".claude"
        && file_name.starts_with("settings")
        && file_name.ends_with(".json")
    {
        return Ruling::Ask(format!(
            "edit of Claude Code settings {} (R26)",
            p.display()
        ));
    }
    if comps.iter().any(|c| c == ".git") {
        return Ruling::Ask(format!("write under .git/: {} (R26)", p.display()));
    }
    if comps.iter().any(|c| c == ".githooks") {
        return Ruling::Ask(format!("edit of a repo hook {} (R26)", p.display()));
    }
    if let Some(why) = super::repo_rules(&p) {
        return Ruling::Ask(why);
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
