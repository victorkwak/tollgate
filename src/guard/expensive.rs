//! R103: commands declared expensive in the repo's `tollgate.toml`
//! (`[[expensive]]`) are refused in their wide form.
//!
//! The guard stops a careless agent that runs a whole browser suite or a
//! workspace-wide test run by hand. A call is wide when its program
//! matches, every `with` word is among its literal argument words, its cwd
//! is under the rule's `cwd`, and no argument matches a `narrow` glob. An
//! argument made at run time counts as narrow. The rules are those of the
//! repo that holds the command's cwd; the walker follows a literal `cd`.
//! Gate jobs and CI are not tool calls, so they still run the wide form.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use globset::GlobSet;

use super::cmds::Arg;
use super::paths;
use super::rules::{self, Ruling};
use crate::config::glob;
use crate::config::repo::Expensive;

/// The rule id (R25).
pub const RULE: &str = "expensive-wide";

/// The longest command text the refusal quotes.
const QUOTE_MAX: usize = 80;

/// The compiled `[[expensive]]` rules of one repo.
#[derive(Debug)]
pub struct Rules {
    root: PathBuf,
    rules: Vec<Rule>,
}

#[derive(Debug)]
struct Rule {
    name: String,
    /// A glob on a repo-relative path (`program` with `/`), or on the
    /// command name's basename.
    program: GlobSet,
    path: bool,
    with: Vec<String>,
    narrow: GlobSet,
    /// Absolute, lexical.
    cwd: Option<PathBuf>,
    hint: String,
    step: Option<String>,
}

/// What the caller already knows about the repo of the call's cwd: its
/// root and its rules. The guard reads that repo's `tollgate.toml` anyway
/// (for `tiers.full_refs`), so the walker reuses that parse.
#[derive(Debug, Clone)]
pub struct Seed {
    pub root: Option<PathBuf>,
    pub rules: Option<Arc<Rules>>,
}

impl Rules {
    /// The rules of the repo at `root`; `None` when it declares none. An
    /// entry whose globs do not compile is skipped (`tollgate config
    /// --check` reports it).
    #[must_use]
    pub fn compile(root: &Path, entries: &[Expensive]) -> Option<Arc<Self>> {
        let rules: Vec<Rule> = entries
            .iter()
            .filter_map(|e| {
                let path = e.program.contains('/');
                let opts = if path {
                    Expensive::PATH_GLOB
                } else {
                    Expensive::WORD_GLOB
                };
                Some(Rule {
                    name: e.name.clone(),
                    program: glob::compile(std::slice::from_ref(&e.program), opts).ok()?,
                    path,
                    with: e.with.clone(),
                    narrow: glob::compile(&e.narrow, Expensive::WORD_GLOB).ok()?,
                    cwd: e.cwd.as_deref().map(|c| paths::lexical(root, Path::new(c))),
                    hint: e.hint.clone(),
                    step: e.step.clone(),
                })
            })
            .collect();
        (!rules.is_empty()).then(|| {
            Arc::new(Self {
                root: root.to_owned(),
                rules,
            })
        })
    }

    /// The ruling on `word args...` run in `cwd`. `file`: a shell reads
    /// `word` as a script file (`bash F`, `source F`), so a bare name is a
    /// path under the cwd too. `typed` is the command as the agent typed
    /// it, for the refusal.
    #[must_use]
    pub fn check(&self, word: &str, file: bool, args: &[Arg], cwd: &Path, typed: &str) -> Ruling {
        for r in &self.rules {
            if r.wide(&self.root, word, file, args, cwd) {
                return Ruling::deny(RULE, r.refusal(typed));
            }
        }
        Ruling::Allow
    }
}

impl Rule {
    fn wide(&self, root: &Path, word: &str, file: bool, args: &[Arg], cwd: &Path) -> bool {
        let program = if self.path {
            // PATH lookup never reads the cwd: a bare name is a path only
            // for a shell that reads it as a script file.
            (file || word.contains('/'))
                && paths::lexical(cwd, Path::new(word))
                    .strip_prefix(root)
                    .is_ok_and(|rel| self.program.is_match(rel))
        } else {
            self.program.is_match(rules::basename(word))
        };
        program
            && self
                .with
                .iter()
                .all(|w| args.iter().any(|a| a.lit() == Some(w.as_str())))
            && self.cwd.as_ref().is_none_or(|c| cwd.starts_with(c))
            && !args.iter().any(|a| a.dynamic || self.narrow.is_match(&a.s))
    }

    fn refusal(&self, typed: &str) -> String {
        let typed = typed.split_whitespace().collect::<Vec<_>>().join(" ");
        let quoted = if typed.chars().count() > QUOTE_MAX {
            let cut: String = typed.chars().take(QUOTE_MAX - 3).collect();
            format!("{cut}...")
        } else {
            typed
        };
        let mut why = format!(
            "`{quoted}` runs all of \"{}\" (tollgate.toml [[expensive]], R103). Narrow form: {}. The whole run belongs to the gate: a push or a merge to a full ref starts it.",
            self.name, self.hint
        );
        if let Some(step) = &self.step {
            why.push_str(&format!(
                " To run or read it now: tollgate run \"{step}\" (a pass of the same inputs is reused)."
            ));
        }
        why
    }
}
