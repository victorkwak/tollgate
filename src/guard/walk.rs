//! The closed grammar (G1-G8) over a parsed Bash command.
//!
//! The walker visits every simple command in the order bash runs them,
//! nested ones included (substitutions, subshells, compound commands,
//! `sh -c` code, `eval` text, script files one level deep, literal
//! heredocs fed to a shell), and holds what the rules need on the way: the
//! cwd (`cd`, `pushd`, `popd`; G8), literal variables, defined functions,
//! the files the command writes, and where each command's stdin comes
//! from. Each simple command must fit its shape:
//!
//! - G1: the command name is a literal word;
//! - G2: wrappers are unwrapped; launchers that leave the session's
//!   environment may not run git, tollgate, a shell or an interpreter;
//! - G3: code in arguments or on stdin is literal and checked as well;
//! - G4: gated git and tollgate commands use literal words and allowed
//!   flags, `-c` keys and variables ([`super::git`]);
//! - G5, G6: sensitive variables are never written;
//! - G7, G8: writes into tollgate's dirs and git's refs, config and hooks
//!   are denied; relative writes after an unknown `cd` too.
//!
//! The first rule that fails denies the call with a message that names the
//! allowed shape.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use super::cmds::{self, Class, Lang, OptValue};
use super::paths;
use super::reach;
use super::rules::{Assessment, Context, Ruling, basename, is_tollgate};
use super::runners::{self, Launch};
use super::shell::{self, AndOr, Command, Kind, Op, Part, Pipeline, Redir, Script, Simple, Word};

/// A deny reason.
pub type Deny = String;
/// A step of the walk: `Err` denies.
pub type W = Result<(), Deny>;

/// The largest script file the guard reads (G3).
const MAX_SCRIPT: u64 = 1 << 20;

/// How deep code in arguments may nest (`sh -c` in `eval` in ...).
const MAX_CODE_DEPTH: usize = 8;

/// How many commands may run one another (`nice nice ... git`, item
/// 21/20): a deeper chain would overflow the guard's stack, and a guard
/// that dies is no answer.
const MAX_RUN_DEPTH: usize = 64;

/// Ways through an `&&`/`||` list followed one by one before they are
/// merged into one.
const MAX_WAYS: usize = 4;

/// The exit status of the part of a list that ran last, as far as the
/// walk knows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Succeeded,
    Failed,
    Unknown,
}

/// Walks of a loop body before its values are given up as unknown.
const MAX_LOOP_PASSES: usize = 6;

/// A `for` loop over at most this many literal items is walked once per
/// item, with the loop variable known.
const MAX_UNROLL: usize = 16;

/// Body walks all unrolled loops of one command may take (L19).
const MAX_UNROLLED_WALKS: usize = 64;

/// The tracked cwd (G8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cwd {
    Known(PathBuf),
    Unknown,
}

/// Where a command's stdin comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feed {
    /// The Bash tool's own stdin.
    Tty,
    Pipe,
    File,
    /// A heredoc or here-string; its text when nothing in it expands.
    Doc(Option<String>),
    Unknown,
}

/// A variable a command gets in its environment from the command line.
#[derive(Debug, Clone)]
pub struct EnvSet {
    pub name: String,
    /// The value, when literal.
    pub value: Option<String>,
    /// Written directly in front of this command (not inherited through a
    /// shell or set by `env`).
    pub prefix: bool,
    /// As written.
    pub raw: String,
}

/// What a write gives a shell variable.
#[derive(Debug, Clone, Copy)]
pub enum Written<'a> {
    /// A value the guard does not know.
    Unknown,
    /// No new value: `unset`, or `export NAME` of the value it holds.
    Kept,
    /// This literal value.
    Value(&'a str),
}

/// What a command inherits from where it runs.
#[derive(Debug, Clone)]
pub struct Frame {
    pub stdin: Feed,
    /// Variables set for it on the command line (prefix assignments,
    /// `env NAME=value`, and those of a shell that runs it).
    pub env: Vec<EnvSet>,
}

impl Frame {
    fn top() -> Self {
        Self {
            stdin: Feed::Tty,
            env: Vec::new(),
        }
    }
}

/// Who runs a command: the shell, or xargs, find -exec or parallel with
/// arguments that come from elsewhere (G2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Shell,
    Elsewhere,
}

/// What a command's environment assignments are checked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    GatedGit,
    Git,
    Tollgate,
    /// A shell, `eval` or `source`: the variables reach the code it runs.
    Code,
    Other,
}

/// G1, G5 (review G5 PATH): the PATH bash searches for a bare command
/// name.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathVal {
    /// The session's PATH: the command has not changed it.
    Session,
    /// Dirs in search order as written (`~` and relative dirs resolve at
    /// the search); `None` is where the session's PATH is spliced in.
    Known(Vec<Option<String>>),
    /// A value bash builds at run time, or one the guard cannot follow.
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
struct Scope {
    /// The PATH bare command names are found on.
    path: PathVal,
    cwd: Cwd,
    oldpwd: Cwd,
    stack: Vec<Cwd>,
    /// Variables with a literal value (`None`: set, value unknown).
    vars: HashMap<String, Option<String>>,
    funcs: BTreeSet<String>,
    /// stdin replaced for the rest of the shell (`exec < file`).
    stdin: Option<Feed>,
    /// Variables not in `vars` are unknown too (after a function call, a
    /// nameref, a trap that can run between commands, or in a body that
    /// runs later), not the session's.
    opaque: bool,
    /// Variables in `vars` with an unknown value that is a number: set by
    /// arithmetic, so safe to use in arithmetic (G3).
    ints: BTreeSet<String>,
}

impl Scope {
    /// What holds after a run that took this path or `other`: a value
    /// known on both and equal stays known, anything else is unknown.
    fn merge(&mut self, other: &Self) {
        let names: BTreeSet<String> = self
            .ints
            .iter()
            .chain(other.ints.iter())
            .chain(self.vars.keys())
            .chain(other.vars.keys())
            .cloned()
            .collect();
        self.ints = names
            .into_iter()
            .filter(|n| self.arith_safe(n) && other.arith_safe(n))
            .collect();
        if self.cwd != other.cwd {
            self.cwd = Cwd::Unknown;
        }
        if self.oldpwd != other.oldpwd {
            self.oldpwd = Cwd::Unknown;
        }
        if self.stack != other.stack {
            self.stack = vec![Cwd::Unknown; self.stack.len().max(other.stack.len())];
        }
        let keys: BTreeSet<String> = self.vars.keys().chain(other.vars.keys()).cloned().collect();
        for k in keys {
            let a = self.vars.get(&k);
            let b = other.vars.get(&k);
            if a != b || (a.is_none() && other.opaque) || (b.is_none() && self.opaque) {
                self.vars.insert(k, None);
            }
        }
        // Either PATH may hold: a name is looked up in the dirs of both
        // (every dir is checked, not only the first match).
        if self.path != other.path {
            let segs = |p: &PathVal| match p {
                PathVal::Session => Some(vec![None]),
                PathVal::Known(k) => Some(k.clone()),
                PathVal::Unknown => None,
            };
            self.path = match (segs(&self.path), segs(&other.path)) {
                (Some(mut a), Some(b)) => {
                    for s in b {
                        if !a.contains(&s) {
                            a.push(s);
                        }
                    }
                    PathVal::Known(a)
                }
                _ => PathVal::Unknown,
            };
        }
        self.opaque |= other.opaque;
        self.funcs.extend(other.funcs.iter().cloned());
        if self.stdin != other.stdin {
            self.stdin = Some(Feed::Unknown);
        }
    }

    /// Nothing is known any more: after a function call or a trap that
    /// can run between commands.
    fn forget(&mut self) {
        self.cwd = Cwd::Unknown;
        self.oldpwd = Cwd::Unknown;
        self.stack = vec![Cwd::Unknown; self.stack.len()];
        self.vars.clear();
        self.ints.clear();
        self.opaque = true;
        self.stdin = Some(Feed::Unknown);
    }
}

impl Scope {
    /// G3: bash evaluates a variable's value as an arithmetic expression
    /// where its name is used in one, and a value like `a[$(cmd)]` runs
    /// `cmd` (`HOME=1` assigns). A name is safe there when its value is a
    /// number, or the session's own.
    fn arith_safe(&self, name: &str) -> bool {
        match self.vars.get(name) {
            Some(Some(v)) => is_number(v),
            Some(None) => self.ints.contains(name),
            None => !self.opaque,
        }
    }
}

/// True for an integer as bash's arithmetic reads it (`12`, `-3`, `0x1f`,
/// `2#101`), or an empty value (0).
fn is_number(v: &str) -> bool {
    let t = v.trim();
    let t = t.strip_prefix(['-', '+']).unwrap_or(t);
    t.is_empty()
        || (t.starts_with(|c: char| c.is_ascii_digit())
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '#' | '@' | '_')))
}

/// Review G7/R25: a path in or above one of tollgate's dirs, and that dir.
type Reached = (PathBuf, PathBuf);

/// The cwd (`None`: unknown) and a word's value.
type ValueKey = (Option<PathBuf>, String);

/// Review G7/R25: what a word names, as far as the guard can tell.
enum Reach {
    /// A path in or above one of tollgate's dirs, and that dir.
    Hit(PathBuf, PathBuf),
    /// No such path.
    Clear,
    /// A part only known at run time.
    Unknown,
    /// Too many brace results or glob entries to check.
    TooMany,
}

/// How a word stands to the Claude Code settings (R26).
enum SettingsReach {
    /// It names this settings path.
    Hit(PathBuf),
    /// No settings path.
    Clear,
    /// A part only known at run time.
    Unknown,
    /// Too many brace results or glob entries to check.
    TooMany,
}

/// The walk's state.
pub struct Walker<'a> {
    pub(super) ctx: &'a Context,
    pub(super) home: String,
    scope: Scope,
    /// The first ask reason (a cell: checks that only read the walk ask
    /// too).
    ask: RefCell<Option<String>>,
    pub(super) long: bool,
    depth: usize,
    in_script: bool,
    /// Files this command writes, removes or replaces, in order.
    written: Vec<PathBuf>,
    /// The exact text of files this command writes once, whole, from a
    /// literal heredoc (`cat > f <<'EOF'`): a later part may run them,
    /// and they are checked as that text (G3).
    known: HashMap<PathBuf, String>,
    /// Files whose mode or owner this command changes (`chmod +x`): a
    /// launcher may run them as programs (G2, item 20).
    moded: Vec<PathBuf>,
    pub(super) saw_git: bool,
    pub(super) saw_tollgate: bool,
    /// [`cmds::scoped`] variables written for the rest of the shell, and
    /// how.
    scoped_writes: Vec<(String, String)>,
    cd_uncertain: bool,
    anchors: HashMap<PathBuf, Vec<String>>,
    /// Every variable write and cwd change, in order (`*`: everything,
    /// `.`: the cwd), for EXIT traps.
    log: Vec<String>,
    /// EXIT trap code, with the scope where it was set and the log
    /// length then: it runs at the end, with what changed since unknown.
    exit_traps: Vec<(String, Scope, usize)>,
    /// The values at each `break` and `continue`, one list per loop being
    /// walked, innermost last: they reach the loop's head or its end
    /// without the rest of the body.
    loops: Vec<Vec<Scope>>,
    /// The values at each `return` from a sourced file, one list per file
    /// being walked: they reach the code after the `.` or `source`.
    returns: Vec<Vec<Scope>>,
    /// Body walks taken by unrolled `for` loops so far.
    unrolled_walks: usize,
    /// How many runners ([`runners`]) the command being walked runs
    /// under: git, tollgate and shells may not run there (item 40).
    pub(super) runner_depth: usize,
    /// G2 (item 21/20, review G2): the programs the guard does not know
    /// whose words are being walked as a command they may run, innermost
    /// last. git under one may run with another environment.
    pub(super) foreign: Vec<String>,
    /// Commands in the chain now being walked ([`MAX_RUN_DEPTH`]).
    run_depth: usize,
    /// G3 (review 39e178e): names declared as namerefs anywhere in the
    /// command, and loop variables of `for` loops over words that may not
    /// be plain names. A `for` loop over a nameref makes each word its
    /// target, so the two sets may not meet: a function body is walked
    /// where it is defined, before a later `declare -n` of its loop
    /// variable.
    namerefs: BTreeSet<String>,
    loose_for: BTreeSet<String>,
    /// Review G7/R25: the command, or a script it runs, spells one of
    /// tollgate's dirs ([`paths::spells_tollgate_dir`]).
    tollgate_named: bool,
    /// R26: the command, or a script it runs, spells a Claude Code
    /// settings name ([`paths::spells_claude`]).
    claude_named: bool,
    /// [`Walker::candidate_reach`] per lexical path and spelling.
    reach_memo: RefCell<HashMap<(PathBuf, bool), Option<Reached>>>,
    /// [`Self::settings_candidate`] results, keyed as `reach_memo`.
    settings_memo: RefCell<HashMap<(PathBuf, bool), Option<PathBuf>>>,
    /// [`Walker::names_tollgate_dir`] per cwd and value.
    value_memo: RefCell<HashMap<ValueKey, Option<Reached>>>,
    /// [`Walker::canon_cached`]: the real path of each dir looked up.
    dir_memo: RefCell<HashMap<PathBuf, PathBuf>>,
    /// Review G7/R25 (L19): the cwd and words of each unknown program
    /// whose words are being walked as a command, all checked: a command
    /// from a tail of them in that cwd needs no second check (code text in
    /// them is new words, and is checked).
    checked_tails: Vec<(Cwd, Vec<String>)>,
    /// G1, G5 (review G5 PATH): bare command names looked up so far.
    path_lookups: usize,
    /// Writes of PATH walked so far, in any code.
    path_writes: usize,
    /// PATH changes where the walk does not see it: a nameref targets it,
    /// or a trap that runs between commands writes it.
    path_hidden: bool,
    /// Functions whose bodies run commands by name, with the PATH their
    /// bodies were checked with: a call with another PATH denies.
    func_paths: HashMap<String, PathVal>,
    /// Functions whose bodies write PATH.
    path_funcs: BTreeSet<String>,
    /// A trap that runs between commands runs commands by name: PATH may
    /// not change after it is set.
    trap_lookups: bool,
}

/// R25/R26/R28 for a Bash command.
#[must_use]
pub fn assess(ctx: &Context, command: &str) -> Assessment {
    let mut w = Walker::new(ctx);
    w.tollgate_named = paths::spells_tollgate_dir(ctx, command);
    w.claude_named = paths::spells_claude(ctx, command);
    let r = match shell::parse(command) {
        Err(e) => Err(format!(
            "the guard cannot parse this command ({e}); write it as plain commands (G1)"
        )),
        Ok(s) => w
            .script(&s, &Frame::top())
            .and_then(|()| w.run_exit_traps())
            .and_then(|()| w.finish()),
    };
    let ruling = match r {
        Err(why) => Ruling::Deny(why),
        Ok(()) => w.ask.take().map_or(Ruling::Allow, Ruling::Ask),
    };
    Assessment {
        ruling,
        long_timeout: w.long,
    }
}

impl<'a> Walker<'a> {
    fn new(ctx: &'a Context) -> Self {
        Self {
            ctx,
            home: ctx.home.to_string_lossy().into_owned(),
            scope: Scope {
                path: PathVal::Session,
                cwd: Cwd::Known(paths::canon(&ctx.cwd)),
                oldpwd: Cwd::Unknown,
                stack: Vec::new(),
                vars: HashMap::new(),
                funcs: BTreeSet::new(),
                stdin: None,
                opaque: false,
                ints: BTreeSet::new(),
            },
            ask: RefCell::new(None),
            long: false,
            depth: 0,
            in_script: false,
            written: Vec::new(),
            known: HashMap::new(),
            moded: Vec::new(),
            saw_git: false,
            saw_tollgate: false,
            scoped_writes: Vec::new(),
            cd_uncertain: false,
            anchors: HashMap::new(),
            log: Vec::new(),
            exit_traps: Vec::new(),
            loops: Vec::new(),
            returns: Vec::new(),
            unrolled_walks: 0,
            runner_depth: 0,
            foreign: Vec::new(),
            run_depth: 0,
            namerefs: BTreeSet::new(),
            loose_for: BTreeSet::new(),
            tollgate_named: false,
            claude_named: false,
            reach_memo: RefCell::new(HashMap::new()),
            settings_memo: RefCell::new(HashMap::new()),
            value_memo: RefCell::new(HashMap::new()),
            dir_memo: RefCell::new(HashMap::new()),
            checked_tails: Vec::new(),
            path_lookups: 0,
            path_writes: 0,
            path_hidden: false,
            func_paths: HashMap::new(),
            path_funcs: BTreeSet::new(),
            trap_lookups: false,
        }
    }

    fn finish(&self) -> W {
        for (name, how) in &self.scoped_writes {
            let Some((reach, why)) = cmds::scoped(name) else {
                continue;
            };
            let hit = match reach {
                cmds::Reach::GitOrTollgate => self.saw_git || self.saw_tollgate,
                cmds::Reach::Tollgate => self.saw_tollgate,
            };
            if hit {
                let who = if reach == cmds::Reach::Tollgate {
                    "tollgate"
                } else {
                    "git or tollgate"
                };
                return Err(format!(
                    "{how} sets {name} in a command that runs {who}; {name} {why} (G5, R8)"
                ));
            }
        }
        Ok(())
    }

    /// EXIT traps run last, with every value that changed after the trap
    /// was set unknown (an `exit`, or `set -e` on any failing command, can
    /// end the shell anywhere after it).
    fn run_exit_traps(&mut self) -> W {
        for _ in 0..MAX_CODE_DEPTH {
            let traps = std::mem::take(&mut self.exit_traps);
            if traps.is_empty() {
                return Ok(());
            }
            for (code, scope, mark) in traps {
                let mut sc = scope;
                for entry in &self.log[mark.min(self.log.len())..] {
                    match entry.as_str() {
                        "*" => sc.forget(),
                        "." => {
                            sc.cwd = Cwd::Unknown;
                            sc.oldpwd = Cwd::Unknown;
                            sc.stack = vec![Cwd::Unknown; sc.stack.len()];
                        }
                        name => {
                            if name == "PATH" {
                                sc.path = PathVal::Unknown;
                            }
                            sc.vars.insert(name.to_owned(), None);
                            sc.ints.remove(name);
                        }
                    }
                }
                self.scope = sc;
                let frame = Frame {
                    stdin: Feed::Unknown,
                    env: Vec::new(),
                };
                self.code(&code, false, &frame, "trap")?;
            }
        }
        Err("traps set traps too deeply to check (G3)".into())
    }

    /// Records an ask (R26); the first reason is kept.
    pub(super) fn ask(&self, why: String) {
        self.ask.borrow_mut().get_or_insert(why);
    }

    pub(super) fn cwd(&self) -> &Cwd {
        &self.scope.cwd
    }

    // ---- structure -------------------------------------------------------

    pub(super) fn script(&mut self, s: &Script, f: &Frame) -> W {
        for ao in &s.items {
            self.and_or(ao, f)?;
        }
        Ok(())
    }

    fn and_or(&mut self, ao: &AndOr, f: &Frame) -> W {
        let saved = ao.background.then(|| self.scope.clone());
        let outer = std::mem::take(&mut self.cd_uncertain);
        let n = ao.rest.len();
        // A `cd` whose failure stops the list: `cd x && ...` or
        // `cd x || exit`.
        let certain = |k: usize| match ao.rest.get(k) {
            Some((true, _)) => true,
            Some((false, next)) => is_exit(next),
            None => false,
        };
        self.pipeline(&ao.first, f, certain(0))?;
        // Each way the list can have gone so far: the values then, and the
        // last status when it is known (`a && b` skipped `b` only because
        // `a` failed). A part runs from every way that reaches it.
        let mut ways: Vec<(Scope, Status)> = vec![(self.scope.clone(), status_of(&ao.first))];
        for k in 1..=n {
            let (and, p) = &ao.rest[k - 1];
            let mut next: Vec<(Scope, Status)> = Vec::new();
            for (st, status) in ways {
                let (runs, skips) = if *and {
                    (status != Status::Failed, status != Status::Succeeded)
                } else {
                    (status != Status::Succeeded, status != Status::Failed)
                };
                if runs {
                    self.scope = st.clone();
                    self.pipeline(p, f, certain(k))?;
                    next.push((self.scope.clone(), status_of(p)));
                }
                if skips {
                    let kept = if *and {
                        Status::Failed
                    } else {
                        Status::Succeeded
                    };
                    next.push((st, kept));
                }
            }
            if next.len() > MAX_WAYS {
                let mut all = next[0].0.clone();
                for (st, _) in &next[1..] {
                    all.merge(st);
                }
                next = vec![(all, Status::Unknown)];
            }
            ways = next;
        }
        let mut end = ways[0].0.clone();
        for (st, _) in &ways[1..] {
            end.merge(st);
        }
        self.scope = end;
        if std::mem::take(&mut self.cd_uncertain) {
            self.scope.cwd = Cwd::Unknown;
        }
        self.cd_uncertain = outer;
        if let Some(s) = saved {
            self.scope = s;
        }
        Ok(())
    }

    fn pipeline(&mut self, p: &Pipeline, f: &Frame, certain: bool) -> W {
        if let [c] = p.cmds.as_slice() {
            return self.command(c, f, certain);
        }
        // Each part of a pipeline runs in a subshell.
        for (k, c) in p.cmds.iter().enumerate() {
            let mut fk = f.clone();
            if k > 0 {
                fk.stdin = Feed::Pipe;
            }
            self.isolated(|w| w.command(c, &fk, false))?;
        }
        Ok(())
    }

    fn isolated(&mut self, f: impl FnOnce(&mut Self) -> W) -> W {
        let saved = self.scope.clone();
        let r = f(self);
        self.scope = saved;
        r
    }

    /// A body that runs zero or more times: it is walked from what holds
    /// before it merged with what holds after each walk, until nothing
    /// changes, so every pass is checked with values that hold on any
    /// iteration.
    ///
    /// `break` and `continue` skip the rest of the body: the values where
    /// they ran reach the head and the end of the loop as well.
    fn looped(&mut self, mut f: impl FnMut(&mut Self) -> W) -> W {
        self.loops.push(Vec::new());
        let r = self.loop_passes(&mut f);
        self.loops.pop();
        r
    }

    fn loop_passes(&mut self, f: &mut impl FnMut(&mut Self) -> W) -> W {
        for _ in 0..MAX_LOOP_PASSES {
            let before = self.scope.clone();
            f(self)?;
            self.merge_jumps();
            self.scope.merge(&before);
            if self.scope == before {
                return Ok(());
            }
        }
        self.scope.forget();
        f(self)?;
        self.scope.forget();
        Ok(())
    }

    /// A `for` loop over literal `values`: the body is walked once per
    /// value, in order, with `name` set to it. The values at a `break` or
    /// `continue` reach every later iteration and the end.
    fn unrolled(&mut self, name: &str, values: &[String], mut f: impl FnMut(&mut Self) -> W) -> W {
        self.loops.push(Vec::new());
        let mut r = Ok(());
        for v in values {
            self.merge_jumps();
            self.scope.vars.insert(name.to_owned(), Some(v.clone()));
            self.scope.ints.remove(name);
            if let Err(e) = f(self) {
                r = Err(e);
                break;
            }
        }
        if r.is_ok() {
            self.merge_jumps();
        }
        self.loops.pop();
        r
    }

    /// Merges the values at the innermost loop's `break`s and `continue`s
    /// into the current ones.
    fn merge_jumps(&mut self) {
        let jumps = self.loops.last().cloned().unwrap_or_default();
        for j in &jumps {
            self.scope.merge(j);
        }
    }

    /// `break [n]` or `continue [n]`: the values now reach the head and
    /// end of the `n`th enclosing loop (every loop when `n` is not a
    /// literal number).
    fn jump(&mut self, arg: Option<&Word>) {
        let n = match arg.map(Word::literal) {
            None => Some(1),
            Some(Some(t)) => t.parse::<usize>().ok().filter(|&n| n > 0),
            Some(None) => None,
        };
        let len = self.loops.len();
        let targets = match n {
            Some(n) => len.saturating_sub(n)..len.min(len.saturating_sub(n) + 1),
            None => 0..len,
        };
        for k in targets {
            self.loops[k].push(self.scope.clone());
        }
    }

    /// Code that runs as its own process or later (a function body, `sh
    /// -c` code, a script run as a child): its jumps never reach the loops
    /// and sourced files walked around it.
    fn detached(&mut self, f: impl FnOnce(&mut Self) -> W) -> W {
        let loops = std::mem::take(&mut self.loops);
        let returns = std::mem::take(&mut self.returns);
        let r = f(self);
        self.loops = loops;
        self.returns = returns;
        r
    }

    fn command(&mut self, c: &Command, f: &Frame, certain: bool) -> W {
        if let Kind::Simple(sc) = &c.kind {
            return self.simple(sc, &c.redirs, f, certain);
        }
        let mut f2 = Frame {
            stdin: self.stdin(f),
            env: f.env.clone(),
        };
        self.redirs(&c.redirs, &mut f2)?;
        match &c.kind {
            Kind::Simple(_) => Ok(()),
            Kind::Subshell(s) => self.isolated(|w| w.script(s, &f2)),
            Kind::Group(s) => self.script(s, &f2),
            Kind::If { arms, other } => {
                // Each body starts after its own condition; the next
                // condition runs only when this one failed.
                let mut ends: Vec<Scope> = Vec::new();
                for (cond, body) in arms {
                    self.script(cond, &f2)?;
                    let after_cond = self.scope.clone();
                    self.script(body, &f2)?;
                    ends.push(std::mem::replace(&mut self.scope, after_cond));
                }
                if let Some(o) = other {
                    self.script(o, &f2)?;
                }
                for e in &ends {
                    self.scope.merge(e);
                }
                Ok(())
            }
            Kind::Loop { cond, body } => self.looped(|w| {
                w.script(cond, &f2)?;
                w.script(body, &f2)
            }),
            Kind::For { var, items, body } => {
                let name = var.literal().ok_or_else(|| {
                    format!("the loop variable `{}` is not a literal name (G5)", var.raw)
                })?;
                for it in items.iter().flatten() {
                    self.word(it, &f2)?;
                }
                self.var_write(&name, "a for loop")?;
                // G3: over a nameref, each word becomes its target. A
                // literal word without `[` (no subscript, no glob) is a
                // plain name or no name at all.
                let plain = items.as_ref().is_some_and(|its| {
                    its.iter()
                        .all(|w| w.literal().is_some_and(|l| !l.contains('[')))
                });
                if !plain {
                    self.loose_for.insert(name.clone());
                    self.nameref_loops()?;
                }
                // Literal items (`for f in a.rs b.rs`): the body is walked
                // once per value, so `$f` is known in it.
                let values: Option<Vec<String>> = items
                    .as_ref()
                    .and_then(|its| its.iter().map(Word::literal).collect());
                match values {
                    Some(vs)
                        if vs.len() <= MAX_UNROLL
                            && self.unrolled_walks + vs.len() <= MAX_UNROLLED_WALKS =>
                    {
                        self.unrolled_walks += vs.len();
                        self.unrolled(&name, &vs, |w| w.script(body, &f2))
                    }
                    _ => {
                        // `for i in $(seq 1 9)`: every value is a number.
                        if items
                            .as_ref()
                            .is_some_and(|its| its.iter().all(|w| self.only_numbers(w)))
                        {
                            self.scope.ints.insert(name.clone());
                        }
                        self.looped(|w| w.script(body, &f2))
                    }
                }
            }
            Kind::ArithFor { header, body } => {
                self.arith(header, &f2)?;
                self.looped(|w| {
                    w.script(body, &f2)?;
                    w.arith(header, &f2)
                })
            }
            Kind::Case { subject, arms } => {
                self.word(subject, &f2)?;
                // An arm may fall through to the next (`;&`): each starts
                // from what holds before the case or after any earlier
                // arm.
                let mut running = self.scope.clone();
                for (pats, body) in arms {
                    self.scope = running.clone();
                    for p in pats {
                        self.word(p, &f2)?;
                    }
                    self.script(body, &f2)?;
                    running.merge(&self.scope);
                }
                self.scope = running;
                Ok(())
            }
            Kind::Func { name, body } => self.func_def(name, body),
            Kind::Cond(words) => {
                for w in words {
                    self.word(w, &f2)?;
                }
                self.test_names(words, true)?;
                // `[[ a -eq b ]]`: both operands are arithmetic.
                for (k, w) in words.iter().enumerate() {
                    let op = w.literal();
                    if !matches!(
                        op.as_deref(),
                        Some("-eq" | "-ne" | "-lt" | "-le" | "-gt" | "-ge")
                    ) {
                        continue;
                    }
                    for side in [k.checked_sub(1), Some(k + 1)].into_iter().flatten() {
                        let Some(o) = words.get(side) else { continue };
                        let text = self.arg_value(o).ok_or_else(|| {
                            format!(
                                "[[ {} {} ]] compares a value the guard does not know as arithmetic, which can run code from it; use [ ] or test (G3)",
                                o.raw,
                                op.as_deref().unwrap_or_default()
                            )
                        })?;
                        if text.contains('`') || text.contains("$(") {
                            return Err(format!(
                                "[[ ]]: `{text}` is evaluated as arithmetic, and code in it runs (G3)"
                            ));
                        }
                        self.arith_reads(&text)?;
                    }
                }
                Ok(())
            }
            Kind::Arith(p) => self.arith(p, &f2),
        }
    }

    fn func_def(&mut self, name: &Word, body: &Command) -> W {
        let n = name
            .literal()
            .ok_or_else(|| format!("the function name `{}` is not literal (G1)", name.raw))?;
        if cmds::reserved_function_name(&n) || is_tollgate(self.ctx, &n) {
            return Err(format!(
                "a function named `{n}` would change what that command runs; the guard does not allow it (G1)"
            ));
        }
        // The body runs later, from wherever it is called.
        let frame = Frame {
            stdin: Feed::Unknown,
            env: Vec::new(),
        };
        let (lookups, writes) = (self.path_lookups, self.path_writes);
        self.detached(|w| {
            w.isolated(|w| {
                w.scope.forget();
                w.command(body, &frame, false)
            })
        })?;
        // G1, G5 (review G5 PATH): the body found its commands on this
        // PATH; a call with another one runs what that PATH finds. Kept
        // over a later definition: another branch may have made this one.
        if self.path_lookups > lookups {
            let now = self.path_now();
            let p = match self.func_paths.get(&n) {
                Some(old) if *old != now => PathVal::Unknown,
                _ => now,
            };
            self.func_paths.insert(n.clone(), p);
        }
        if self.path_writes > writes {
            self.path_funcs.insert(n.clone());
        }
        self.scope.funcs.insert(n);
        Ok(())
    }

    /// The commands a word runs while bash builds it, and the variables it
    /// assigns (`${NAME:=value}`).
    fn word(&mut self, w: &Word, f: &Frame) -> W {
        let frame = Frame {
            stdin: self.stdin(f),
            env: Vec::new(),
        };
        for s in w.scripts() {
            self.isolated(|me| me.script(s, &frame))?;
        }
        self.param_writes(&w.parts)
    }

    fn param_writes(&mut self, parts: &[Part]) -> W {
        for p in parts {
            match p {
                Part::Double(inner) => self.param_writes(inner)?,
                Part::Param(text, subs) => {
                    let Some(inner) = text.strip_prefix('{').and_then(|t| t.strip_suffix('}'))
                    else {
                        continue;
                    };
                    self.param_arith(inner, !subs.is_empty())?;
                    if inner.ends_with("@P") {
                        return Err(format!(
                            "`${{{inner}}}` expands a value as a prompt, which runs command substitutions in it (G3)"
                        ));
                    }
                    if inner.starts_with('!') && inner.contains('=') {
                        return Err(format!(
                            "`${{{inner}}}` assigns a variable named at run time (G5)"
                        ));
                    }
                    if let Some(ind) = inner.strip_prefix('!') {
                        let end = ind
                            .char_indices()
                            .skip(1)
                            .find(|&(_, c)| {
                                matches!(
                                    c,
                                    ':' | '-' | '+' | '=' | '?' | '#' | '%' | '/' | '^' | ',' | '@'
                                )
                            })
                            .map_or(ind.len(), |(k, _)| k);
                        let (head, tail) = ind.split_at(end);
                        // `${!prefix@}` lists names; `${!x@Q}` reads x's
                        // value as a name. `${!a[@]}` lists keys, but with
                        // an operator (`${!a[@]:-x}`) it reads every
                        // element as a name.
                        if tail == "@" || (head.contains('[') && !tail.is_empty()) {
                            self.indirection(ind)?;
                        } else {
                            self.indirection(head)?;
                        }
                    }
                    let name: String = inner
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    let mut rest = &inner[name.len()..];
                    if rest.starts_with('[') {
                        rest = rest.find(']').map_or("", |k| &rest[k + 1..]);
                    }
                    if rest.starts_with(":=") || rest.starts_with('=') || rest.starts_with("::=") {
                        self.var_write(&name, "`${NAME:=value}`")?;
                    }
                }
                Part::Arith(text, subs) => {
                    if !subs.iter().all(|sub| self.numeric_output(sub)) {
                        return Err(format!(
                            "`$(({text}))` evaluates command output as arithmetic, which runs code from a value like a[$(cmd)]; compute it in a separate step or check the number first (G3)"
                        ));
                    }
                    self.arith_names(text)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// True when every value `w` can have is made of numbers: a literal
    /// number, arithmetic (`$((n+1))`), or the output of a command that
    /// prints only numbers (`$(date +%s)`, `$(wc -l < f)`, `$(seq 1 9)`).
    fn only_numbers(&self, w: &Word) -> bool {
        if let Some(l) = w.literal() {
            return l.split_whitespace().all(is_number);
        }
        let part_ok = |p: &Part| match p {
            Part::Arith(_, subs) => subs.iter().all(|sub| self.numeric_output(sub)),
            Part::CmdSub(sub) | Part::Backtick(sub) => self.numeric_output(sub),
            _ => false,
        };
        !w.parts.is_empty()
            && w.parts.iter().all(|p| match p {
                Part::Double(inner) => !inner.is_empty() && inner.iter().all(part_ok),
                other => part_ok(other),
            })
    }

    /// True when `s` prints only numbers and blanks: one pipeline whose
    /// last command is `wc -l|-c|-w|-m` on stdin, `date` with a format of
    /// digit fields only, `seq` of literal numbers, `nproc`, `id -u|-g`,
    /// `grep -c` on at most one file, or `git rev-list --count`.
    fn numeric_output(&self, s: &Script) -> bool {
        let [ao] = s.items.as_slice() else {
            return false;
        };
        if !ao.rest.is_empty() || ao.background {
            return false;
        }
        let Some(last) = ao.first.cmds.last() else {
            return false;
        };
        let Kind::Simple(sc) = &last.kind else {
            return false;
        };
        if !sc.assigns.is_empty()
            || self.scope.vars.contains_key("PATH")
            || self.scope.opaque
            || last
                .redirs
                .iter()
                .any(|r| r.writes_file() || r.fd.is_some_and(|fd| fd == 1))
        {
            return false;
        }
        let Some(words) = sc
            .words
            .iter()
            .map(Word::literal)
            .collect::<Option<Vec<String>>>()
        else {
            return false;
        };
        let Some(name) = words.first() else {
            return false;
        };
        if self.scope.funcs.contains(name.as_str()) {
            return false;
        }
        let args = &words[1..];
        match basename(name) {
            "wc" => {
                !args.is_empty()
                    && args.iter().all(|a| {
                        matches!(
                            a.as_str(),
                            "-l" | "-c"
                                | "-w"
                                | "-m"
                                | "--lines"
                                | "--bytes"
                                | "--words"
                                | "--chars"
                        )
                    })
            }
            "date" => {
                let mut fmt = false;
                let mut k = 0;
                while k < args.len() {
                    let a = &args[k];
                    if let Some(f) = a.strip_prefix('+') {
                        let mut it = f.chars();
                        let mut ok = true;
                        while let Some(ch) = it.next() {
                            if ch == '%' {
                                if !it
                                    .next()
                                    .is_some_and(|c| "sNYmdHMSjuwVGgCyeklI%".contains(c))
                                {
                                    ok = false;
                                }
                            } else if !(ch.is_ascii_digit() || ch == ' ') {
                                ok = false;
                            }
                        }
                        if !ok {
                            return false;
                        }
                        fmt = true;
                    } else if matches!(a.as_str(), "-d" | "-r" | "--date" | "--reference") {
                        k += 1;
                    } else if !(a == "-u"
                        || a == "--utc"
                        || a.starts_with("--date=")
                        || a.starts_with("--reference="))
                    {
                        return false;
                    }
                    k += 1;
                }
                fmt
            }
            "seq" => !args.is_empty() && args.len() <= 3 && args.iter().all(|a| is_number(a)),
            "nproc" => args.is_empty(),
            "id" => matches!(args, [a] if a == "-u" || a == "-g"),
            "grep" | "rg" => {
                let count = args.iter().any(|a| {
                    a == "--count"
                        || (a.starts_with('-') && !a.starts_with("--") && a.contains('c'))
                });
                let named = args.iter().any(|a| {
                    a == "--with-filename"
                        || a == "-r"
                        || a == "--recursive"
                        || (a.starts_with('-')
                            && !a.starts_with("--")
                            && (a.contains('H') || a.contains('r') || a.contains('R')))
                });
                let operands = args.iter().filter(|a| !a.starts_with('-')).count();
                basename(name) == "grep" && count && !named && operands <= 2
            }
            "git" => {
                args.first().is_some_and(|a| a == "rev-list") && args.iter().any(|a| a == "--count")
            }
            _ => false,
        }
    }

    /// `${a[sub]}` and `${s:offset:length}`: the subscript and the numbers
    /// are arithmetic (G3).
    fn param_arith(&self, inner: &str, runs: bool) -> W {
        let inner = inner.trim_start_matches(['#', '!']);
        let name_len = inner
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .unwrap_or(inner.len());
        let rest = &inner[name_len..];
        let arith = if let Some(r) = rest.strip_prefix('[') {
            let end = r.find(']').unwrap_or(r.len());
            let sub = &r[..end];
            if sub == "@" || sub == "*" {
                // `${a[@]:off:len}`
                r[end..].strip_prefix(']').and_then(|t| substring_part(t))
            } else {
                Some(sub)
            }
        } else {
            substring_part(rest)
        };
        let Some(text) = arith else {
            return Ok(());
        };
        if runs || text.contains('`') || text.contains("$(") {
            return Err(format!(
                "`${{{inner}}}`: bash evaluates `{text}` as arithmetic, and code in it or in a value it reads runs (G3)"
            ));
        }
        self.arith_reads(text)
    }

    /// G3: every name `text` reads in arithmetic has a value that is a
    /// number (or the session's).
    fn arith_reads(&self, text: &str) -> W {
        let text = &without_lengths(text);
        let c: Vec<char> = text.chars().collect();
        for k in 0..c.len() {
            if c[k] != '$' {
                continue;
            }
            let next = c.get(k + 1).copied();
            let after_brace = (next == Some('{')).then(|| c.get(k + 2).copied()).flatten();
            let positional = |ch: Option<char>| {
                ch.is_some_and(|ch| ch.is_ascii_digit() || ch == '@' || ch == '*')
            };
            if positional(next) || positional(after_brace) {
                return Err(format!(
                    "arithmetic `{text}` reads a positional parameter, whose value the guard does not know; bash evaluates it as an expression, which can run code (G3)"
                ));
            }
        }
        for id in cmds::identifiers(text) {
            if !self.scope.arith_safe(id) {
                return Err(format!(
                    "arithmetic reads `{id}`, whose value the guard does not know; bash evaluates it as an expression, and a value like a[$(cmd)] runs cmd, so compute it where its value is a literal number (G3)"
                ));
            }
        }
        Ok(())
    }

    /// `NAME[sub]=value`: the subscript is arithmetic (G3).
    fn subscript_check(&self, raw: &str, name: &str) -> W {
        let Some(rest) = raw.strip_prefix(name).and_then(|r| r.strip_prefix('[')) else {
            return Ok(());
        };
        let Some(end) = rest.find("]=").or_else(|| rest.find("]+=")) else {
            return Ok(());
        };
        let sub = &rest[..end];
        if sub.contains('`') || sub.contains("$(") {
            return Err(format!(
                "`{name}[{sub}]=`: bash evaluates the subscript as arithmetic, and code in it runs (G3)"
            ));
        }
        self.arith_reads(sub)
    }

    /// G3 (review 39e178e): `text` is a word bash reads as a variable name
    /// (`test -v`, `printf -v`, `read`, `unset`, `declare`, `${!x}`, a
    /// nameref target). It may name an array element, and bash expands
    /// and evaluates the subscript, running the substitutions in it, so
    /// it must be `NAME`, `NAME[@]`, `NAME[*]` or `NAME[sub]` with plain
    /// arithmetic `sub`. Returns `NAME`.
    fn name_ref<'t>(&self, text: &'t str, how: &str) -> Result<&'t str, String> {
        let deny = || {
            format!(
                "{how} `{text}`: bash reads it as a variable name and evaluates a subscript in it, which can run code; use a literal NAME or NAME[number] (G3)"
            )
        };
        let (name, sub) = match text.split_once('[') {
            Some((n, rest)) => (n, Some(rest.strip_suffix(']').ok_or_else(deny)?)),
            None => (text, None),
        };
        if !shell::is_name(name) {
            return Err(deny());
        }
        match sub {
            None | Some("@" | "*") => Ok(name),
            Some(sub) => {
                // Arithmetic text only: no expansion, quote or escape
                // (`$(`, backquotes, `<(`, `\x24`) reaches bash's
                // expansion of the subscript.
                let plain =
                    |c: char| c.is_ascii_alphanumeric() || " _+-*/%<>=!&|^~?:,()[].#".contains(c);
                if sub.is_empty()
                    || !sub.chars().all(plain)
                    || sub.contains("<(")
                    || sub.contains(">(")
                {
                    return Err(deny());
                }
                self.arith_reads(sub)
                    .map_err(|e| format!("{how} `{text}`: {e}"))?;
                Ok(name)
            }
        }
    }

    /// `test -v NAME`, `[ -R NAME ]`, `[[ -v NAME ]]`: bash evaluates a
    /// subscript in the operand. `words` are the operands after the
    /// command name; `cond` is `[[ ]]`, where no word is globbed and an
    /// operator is never built at run time.
    fn test_names(&self, words: &[Word], cond: bool) -> W {
        let value = |w: &Word| {
            if cond {
                let w2 = Word {
                    parts: w
                        .parts
                        .iter()
                        .map(|p| match p {
                            Part::Glob(c) => Part::Lit(c.to_string()),
                            other => other.clone(),
                        })
                        .collect(),
                    brace: false,
                    raw: w.raw.clone(),
                };
                self.arg_value(&w2)
            } else {
                self.arg_value(w)
            }
        };
        for (k, op) in words.iter().enumerate() {
            let Some(next) = words.get(k + 1) else {
                break;
            };
            let op = value(op);
            // An operator bash builds at run time may be `-v`, except in
            // `[[ ]]`, which parses operators first.
            if cond && op.is_none() {
                continue;
            }
            if op.as_deref().is_some_and(|o| o != "-v" && o != "-R") {
                continue;
            }
            let how = format!("test {}", op.as_deref().unwrap_or("-v"));
            match value(next) {
                // No `[`: bash looks the name up and evaluates nothing.
                Some(v) if !v.contains('[') => {}
                // `[ x = -v ]`: the closing bracket.
                Some(v) if !cond && v == "]" && k + 2 == words.len() => {}
                Some(v) => {
                    self.name_ref(&v, &how)?;
                }
                None if op.is_none() => {
                    return Err(format!(
                        "test with `{}` and `{}`, both built at run time: the first may be -v, and bash evaluates a subscript in the second (G3)",
                        words[k].raw, next.raw
                    ));
                }
                None => {
                    return Err(format!(
                        "{how} `{}`: a variable name bash builds at run time can name an array element whose subscript runs code (G3)",
                        next.raw
                    ));
                }
            }
        }
        Ok(())
    }

    /// `${!x}`: bash reads the value of `x` as a variable name, and
    /// evaluates a subscript in it (G3, review 39e178e). `ind` is the text
    /// after the `!`.
    fn indirection(&self, ind: &str) -> W {
        let name: String = ind
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let rest = &ind[name.len()..];
        if shell::is_name(&name) && matches!(rest, "*" | "@" | "[@]" | "[*]") {
            // `${!prefix*}`, `${!a[@]}`: names and keys, nothing is read
            // as a name.
            return Ok(());
        }
        if name.is_empty() && rest.starts_with('#') && !rest.starts_with("##") {
            // `${!#}`: the last positional parameter; its name is a number.
            return Ok(());
        }
        let deny = |why: &str| {
            format!(
                "`${{!{ind}}}` reads {why} as a variable name, and bash evaluates a subscript in it, which can run code (G3)"
            )
        };
        if !shell::is_name(&name) || rest.starts_with('[') {
            return Err(deny("a value the guard does not know"));
        }
        let v = self
            .lookup(&name)
            .ok_or_else(|| deny(&format!("`{name}`, whose value the guard does not know,")))?;
        if v.contains('[') {
            self.name_ref(&v, &format!("`${{!{ind}}}`"))?;
        }
        Ok(())
    }

    /// A `for` loop over a nameref makes each of its words the target.
    fn nameref_loops(&self) -> W {
        if let Some(n) = self.namerefs.intersection(&self.loose_for).next() {
            return Err(format!(
                "`{n}` is a nameref and the variable of a for loop over words that may not be plain names: bash makes each word its target and evaluates a subscript in it, which can run code (G3)"
            ));
        }
        Ok(())
    }

    fn arith(&mut self, p: &Part, f: &Frame) -> W {
        let w = Word {
            parts: vec![p.clone()],
            ..Word::default()
        };
        self.word(&w, f)
    }

    /// Arithmetic can assign any variable it names (`(( HOME = 1 ))`), and
    /// it evaluates the value of every name it reads (G3).
    /// The caller checks the substitutions in it (their output must be
    /// numbers, [`Self::numeric_output`]).
    fn arith_names(&mut self, text: &str) -> W {
        self.arith_reads(text)?;
        for id in cmds::identifiers(text) {
            if id == "TOLLGATE_INLINE_CAP"
                || cmds::sensitive(id).is_some()
                || cmds::scoped(id).is_some()
            {
                self.var_write(id, "an arithmetic expression")?;
            }
        }
        for id in arith_assigned(text) {
            // `(( x = 1 ))`, `x++`: the value is a number now (every name
            // read was one).
            self.scope.vars.insert(id.to_owned(), None);
            self.scope.ints.insert(id.to_owned());
            self.log.push(id.to_owned());
        }
        Ok(())
    }

    /// The command's stdin: the frame's, or the shell's after `exec <`.
    fn stdin(&self, f: &Frame) -> Feed {
        match (&f.stdin, &self.scope.stdin) {
            (Feed::Tty, Some(s)) => s.clone(),
            (s, _) => s.clone(),
        }
    }

    fn redirs(&mut self, rs: &[Redir], f: &mut Frame) -> W {
        for r in rs {
            self.word(&r.target, f)?;
            if let Some(d) = &r.doc {
                let w = Word {
                    parts: d.borrow().parts.clone(),
                    ..Word::default()
                };
                self.word(&w, f)?;
            }
            if let Some(v) = &r.var {
                self.var_write(v, "a `{NAME}>` redirection")?;
            }
            if r.writes_file() {
                self.write_target(&r.target, false, "a redirection")?;
            }
            if r.feeds_stdin() {
                f.stdin = match r.op {
                    Op::Here => Feed::Doc(r.doc.as_ref().and_then(|d| d.borrow().literal())),
                    Op::HereStr => Feed::Doc(r.target.literal().map(|t| format!("{t}\n"))),
                    Op::DupIn if r.target.literal().as_deref() == Some("-") => Feed::Tty,
                    Op::DupIn => Feed::Unknown,
                    _ => Feed::File,
                };
            }
        }
        Ok(())
    }

    // ---- simple commands --------------------------------------------------

    fn simple(&mut self, sc: &Simple, redirs: &[Redir], f: &Frame, certain: bool) -> W {
        for a in &sc.assigns {
            for v in &a.value {
                self.word(v, f)?;
            }
        }
        for w in &sc.words {
            self.word(w, f)?;
        }
        let mut f2 = Frame {
            stdin: self.stdin(f),
            env: f.env.clone(),
        };
        self.redirs(redirs, &mut f2)?;
        if sc.words.is_empty() {
            for a in &sc.assigns {
                self.subscript_check(&a.raw, &a.name)?;
                let value = (!a.array)
                    .then(|| {
                        a.value
                            .first()
                            .and_then(|v| self.resolve(v).or_else(|| self.mktemp_value(v)))
                    })
                    .flatten();
                let appends = a.raw.starts_with(&format!("{}+=", a.name));
                let written = match value.as_deref() {
                    Some(v) if !appends => Written::Value(v),
                    _ => Written::Unknown,
                };
                let path =
                    (a.name == "PATH" && !a.array).then(|| self.path_of(a.value.first(), appends));
                self.var_set(&a.name, "an assignment", written)?;
                if let Some(p) = path
                    && !self.path_hidden
                {
                    self.scope.path = p;
                }
                let number = !a.array && a.value.first().is_some_and(|v| self.only_numbers(v));
                self.scope.vars.insert(a.name.clone(), value);
                if number {
                    self.scope.ints.insert(a.name.clone());
                }
            }
            return Ok(());
        }
        let name = self.command_word(&sc.words[0])?;
        // `exec < file`: stdin for the rest of the shell.
        if name == "exec" && sc.words.len() == 1 {
            if redirs.iter().any(Redir::feeds_stdin) {
                self.scope.stdin = Some(f2.stdin.clone());
            }
            return Ok(());
        }
        let mut env: Vec<EnvSet> = f
            .env
            .iter()
            .map(|e| EnvSet {
                prefix: false,
                ..e.clone()
            })
            .collect();
        for a in &sc.assigns {
            env.push(EnvSet {
                name: a.name.clone(),
                value: (!a.array)
                    .then(|| a.value.first().and_then(Word::literal))
                    .flatten(),
                prefix: true,
                raw: a.raw.clone(),
            });
        }
        // G1, G5: bash finds the command on a PATH written in front of it.
        let path = sc.assigns.iter().rev().find(|a| a.name == "PATH").map(|a| {
            if a.array {
                PathVal::Unknown
            } else {
                let appends = a.raw.starts_with("PATH+=");
                self.path_of(a.value.first(), appends)
            }
        });
        self.with_path(path, |w| {
            w.run(&sc.words, &name, env, &f2, Via::Shell, certain)
        })?;
        self.note_known(sc, redirs, &f2.stdin);
        Ok(())
    }

    /// G1: the command name as bash runs it, or a deny.
    pub(super) fn command_word(&self, w: &Word) -> Result<String, Deny> {
        if let Some(l) = w.literal_home(&self.home) {
            return Ok(l);
        }
        // A name built only from variables this command set to literal
        // values (`B=/abs/bin/tool; $B args`), never from the session's.
        if !self.ifs_set()
            && let Some(v) = w.value(
                &|n| self.scope.vars.get(n).cloned().flatten(),
                Some(&self.home),
            )
            && !v.is_empty()
        {
            return Ok(v);
        }
        Err({
            format!(
                "the command name `{}` is not a literal word; the guard runs only commands named literally (no $, backquotes, $(...), <(...), $'...', globs or braces) (G1)",
                w.raw
            )
        })
    }

    /// True when this command assigns `IFS`: word splitting then differs
    /// from the default, so no unquoted expansion is resolved.
    fn ifs_set(&self) -> bool {
        self.scope.vars.contains_key("IFS") || self.scope.opaque
    }

    /// The value `NAME=$(mktemp ...)` gives: a new path in the dir mktemp
    /// uses (`-p`, `--tmpdir`, a template with a `/`, else `TMPDIR` or
    /// `/tmp`). Writes under it are checked against that dir.
    fn mktemp_value(&self, w: &Word) -> Option<String> {
        let script = match w.parts.as_slice() {
            [Part::CmdSub(s)] => s,
            [Part::Double(inner)] => match inner.as_slice() {
                [Part::CmdSub(s)] => s,
                _ => return None,
            },
            _ => return None,
        };
        let [ao] = script.items.as_slice() else {
            return None;
        };
        if !ao.rest.is_empty() || ao.background || ao.first.negate {
            return None;
        }
        let [c] = ao.first.cmds.as_slice() else {
            return None;
        };
        let Kind::Simple(sc) = &c.kind else {
            return None;
        };
        if c.redirs.iter().any(|r| r.fd != Some(2)) {
            return None;
        }
        let lits = self.lits(&sc.words);
        if lits.first()?.as_deref() != Some("mktemp") || lits.iter().any(Option::is_none) {
            return None;
        }
        let mut tmpdir = match sc.assigns.iter().find(|a| a.name == "TMPDIR") {
            Some(a) => Some(a.value.first().and_then(Word::literal)?),
            None => self.lookup("TMPDIR"),
        }
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "/tmp".into());
        let mut template: Option<String> = None;
        let mut k = 1;
        let lits: Vec<String> = lits.into_iter().flatten().collect();
        while k < lits.len() {
            let a = &lits[k];
            if a == "-p" {
                tmpdir.clone_from(lits.get(k + 1)?);
                k += 2;
                continue;
            }
            if let Some(d) = a.strip_prefix("--tmpdir=") {
                d.clone_into(&mut tmpdir);
            } else if let Some(d) = a.strip_prefix("-p") {
                d.clone_into(&mut tmpdir);
            } else if let Some(sfx) = a.strip_prefix("--suffix=") {
                if sfx.contains('/') {
                    return None;
                }
            } else if a == "--suffix" {
                return None;
            } else if let Some(flags) = a.strip_prefix('-') {
                if !flags.chars().all(|c| "dqtu".contains(c))
                    && !matches!(
                        a.as_str(),
                        "--directory" | "--quiet" | "--dry-run" | "--tmpdir"
                    )
                {
                    return None;
                }
            } else if template.replace(a.clone()).is_some() {
                return None;
            }
            k += 1;
        }
        let name = match template {
            Some(t) if t.contains('/') => return Some(t),
            Some(t) => t,
            None => "tmp.XXXXXXXXXX".into(),
        };
        Some(format!("{}/{name}", tmpdir.trim_end_matches('/')))
    }

    /// The literal words of `argv` (`~` resolved); `None` for others.
    pub(super) fn lits(&self, argv: &[Word]) -> Vec<Option<String>> {
        argv.iter().map(|w| w.literal_home(&self.home)).collect()
    }

    /// The class of command `name`: a path word goes by the basename of
    /// what it resolves to (a link named `g` to git is git).
    pub(super) fn class_of(&self, name: &str) -> (String, Class) {
        let mut base = basename(name).to_owned();
        if name.contains('/')
            && let Some(p) = self.abs_path(name)
            && let Ok(real) = std::fs::canonicalize(&p)
            && let Some(b) = real.file_name()
        {
            base = b.to_string_lossy().into_owned();
        }
        let class = cmds::classify(&base);
        (base, class)
    }

    /// Runs `argv` (its name `name`, literal) with `env`.
    pub(super) fn run(
        &mut self,
        argv: &[Word],
        name: &str,
        env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
        certain: bool,
    ) -> W {
        if self.run_depth >= MAX_RUN_DEPTH {
            return Err(format!(
                "`{name}` is run by more than {MAX_RUN_DEPTH} commands in a chain; too deep to check (G2)"
            ));
        }
        self.run_depth += 1;
        let r = self.run_command(argv, name, env, f, via, certain);
        self.run_depth -= 1;
        r
    }

    fn run_command(
        &mut self,
        argv: &[Word],
        name: &str,
        env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
        certain: bool,
    ) -> W {
        // G1, G5 (review G5 PATH): bash finds a bare name that is not a
        // builtin or a function on PATH; a file found in a dir this
        // command puts there runs instead of the session's program, and
        // is checked as what it is.
        if !name.is_empty()
            && !name.contains('/')
            && !cmds::bash_builtin(name)
            && !self.scope.funcs.contains(name)
        {
            self.path_lookups += 1;
            for hit in self.path_hits(name)? {
                self.run_command(argv, &hit, env.clone(), f, via, certain)?;
            }
        }
        let (base, class) = self.class_of(name);
        if class == Class::Other {
            match name {
                "break" | "continue" => self.jump(argv.get(1)),
                "return" => {
                    if let Some(r) = self.returns.last_mut() {
                        r.push(self.scope.clone());
                    }
                }
                _ => {}
            }
        }
        let lower = base.to_ascii_lowercase();
        if lower != base
            && (lower == "git"
                || lower.starts_with("git-")
                || lower == "tollgate"
                || runners::is_runner(&lower)
                || cmds::classify(&lower) != Class::Other)
        {
            return Err(format!(
                "`{name}`: write the command name in lowercase; a case-insensitive file system runs {lower} for it (G1)"
            ));
        }
        let gitish = base == "git"
            || base
                .strip_prefix("git-")
                .is_some_and(|s| super::git::KNOWN.contains(&s));
        let tollgate = is_tollgate(self.ctx, name) || base == "tollgate";
        if name.contains('/')
            && (gitish || tollgate || class != Class::Other || runners::is_runner(&base))
        {
            let strict = gitish
                || tollgate
                || matches!(class, Class::Shell(_) | Class::Opaque(_) | Class::Interp(_));
            if self.shell_script_named(name, &base, strict)? {
                return self.path_command(name, &base, argv, env, f, via);
            }
        }
        // A shell word of a program the guard does not know may be data
        // (`uv run pytest -k bash tests/`): it runs nothing when it gets
        // no code and its one script is not there (item 21/20).
        let inert_word = !self.foreign.is_empty()
            && matches!(class, Class::Shell(_) | Class::Opaque(_))
            && match argv.get(1..).unwrap_or_default() {
                [] => self.stdin(f) == Feed::Tty,
                [w] => w
                    .literal_home(&self.home)
                    .filter(|a| !a.starts_with(['-', '+']))
                    .is_some_and(|a| self.runs_nothing(&a, &env)),
                _ => false,
            };
        if self.runner_depth > 0
            && !inert_word
            && (gitish
                || tollgate
                || matches!(class, Class::Shell(_) | Class::Opaque(_) | Class::Busybox))
        {
            return Err(format!(
                "`{name}` under a runner (uv run, npx, strace, ...): the runner may find another program by that name, or trace or detach it; run it directly in the session (G2, item 40)"
            ));
        }
        if gitish {
            self.path_words(name, &argv[1..], &env, Some(via))?;
            if let Some(prog) = self.foreign.last().cloned() {
                return self.foreign_git(&prog, argv, env, f, via);
            }
            return self.git(argv, env, f, via);
        }
        if tollgate {
            return self.tollgate(argv, env, via);
        }
        if matches!(class, Class::Other | Class::Interp(Lang::Bun)) && runners::is_runner(&base) {
            let lits = self.lits(argv);
            if let Some(l) = runners::launch(&base, &lits) {
                return self.runner(&base, l, argv, env, f, via, certain);
            }
        }
        if matches!(base.as_str(), "test" | "[") {
            self.test_names(&argv[1..], false)?;
        }
        match class {
            Class::Wrapper(w) => self.wrapper(w, argv, env, f, via, certain),
            Class::Launcher(l) => {
                self.path_words(name, &argv[1..], &env, Some(via))?;
                self.launcher(l, argv, env, f, via)
            }
            Class::Shell(sh) => {
                self.path_words(name, &argv[1..], &env, Some(via))?;
                self.shell(sh, argv, env, f, via)
            }
            Class::Opaque(o) => self.opaque(o, argv, env, f, via),
            Class::Eval => {
                self.no_elsewhere(via, "eval")?;
                self.env_check(&env, Target::Code)?;
                let lits = self.lits(&argv[1..]);
                let Some(parts) = lits.into_iter().collect::<Option<Vec<String>>>() else {
                    return Err(
                        "eval of text bash builds at run time: the guard checks only literal code (G3)"
                            .into(),
                    );
                };
                let frame = Frame {
                    stdin: f.stdin.clone(),
                    env,
                };
                self.code(&parts.join(" "), false, &frame, "eval")
            }
            Class::Source => {
                self.no_elsewhere(via, name)?;
                self.env_check(&env, Target::Code)?;
                self.path_words(name, &argv[1..], &env, Some(via))?;
                let mut i = 1;
                if argv.get(1).and_then(Word::literal).as_deref() == Some("--") {
                    i = 2;
                }
                let Some(file) = argv.get(i) else {
                    return Ok(());
                };
                self.script_file(file, false, env, f, name)
            }
            Class::Interp(lang) => {
                self.path_words(name, &argv[1..], &env, Some(via))?;
                self.interp(lang, &base, argv, env, f, via)
            }
            Class::VarWrite(b) => self.var_writer(b, argv, &env),
            Class::Cd(b) => {
                self.env_check(&env, Target::Other)?;
                self.cd(b, argv, certain)
            }
            Class::Busybox => {
                let Some(applet) = argv.get(1).and_then(|w| w.literal_home(&self.home)) else {
                    return Ok(());
                };
                self.run(&argv[1..], &applet, env, f, via, certain)
            }
            Class::Other => {
                if name.contains('/') {
                    self.path_command(name, &base, argv, env, f, via)
                } else {
                    self.other(name, &base, argv, &env, f, via)
                }
            }
        }
    }

    fn no_elsewhere(&self, via: Via, what: &str) -> W {
        if via == Via::Elsewhere {
            return Err(format!(
                "xargs, find -exec and parallel run {what} with arguments from elsewhere; the guard cannot check them (G2)"
            ));
        }
        Ok(())
    }

    /// G4, G5, G6: the variables a command gets on its command line.
    pub(super) fn env_check(&mut self, env: &[EnvSet], t: Target) -> W {
        let gitish = matches!(t, Target::GatedGit | Target::Git | Target::Tollgate);
        for e in env {
            if e.name == "TOLLGATE_INLINE_CAP" {
                let n = e
                    .value
                    .as_deref()
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse::<u64>().ok());
                if !(e.prefix && gitish && n.is_some_and(|n| n <= self.ctx.inline_cap)) {
                    return Err(format!(
                        "`{}`: TOLLGATE_INLINE_CAP may only be a literal number of seconds up to {} written in front of git or tollgate itself (G6)",
                        e.raw, self.ctx.inline_cap
                    ));
                }
                continue;
            }
            if let Some(why) = cmds::sensitive(&e.name) {
                return Err(format!("`{}` sets {}, which {why} (G5)", e.raw, e.name));
            }
            if let Some(r) = cmds::program_var(&e.name) {
                let appends = e.raw.starts_with(&format!("{}+=", e.name));
                let v = e.value.as_deref().filter(|_| !appends);
                self.program_var(&e.name, r, v, &format!("`{}`", e.raw))?;
            }
            if let Some((reach, why)) = cmds::scoped(&e.name) {
                let hit = match reach {
                    cmds::Reach::GitOrTollgate => gitish,
                    cmds::Reach::Tollgate => t == Target::Tollgate,
                };
                if hit {
                    return Err(format!(
                        "`{}` sets {} for git or tollgate; {} {why} (G5, R8)",
                        e.raw, e.name, e.name
                    ));
                }
            }
            if matches!(t, Target::GatedGit | Target::Tollgate) {
                if !cmds::GATED_ENV.contains(&e.name.as_str()) {
                    return Err(format!(
                        "`{}`: only {} may be set in front of a gated git or tollgate command (G4)",
                        e.raw,
                        cmds::GATED_ENV.join(", ")
                    ));
                }
                if e.value.is_none() {
                    return Err(format!(
                        "`{}`: a variable in front of a gated git or tollgate command needs a literal value (G4)",
                        e.raw
                    ));
                }
            }
        }
        Ok(())
    }

    /// G5: a write of shell variable `name` (assignment, `export`,
    /// `declare`, `read`, ...) with a value the guard does not know.
    pub(super) fn var_write(&mut self, name: &str, how: &str) -> W {
        self.var_set(name, how, Written::Unknown)
    }

    /// G5, item 21: a write of shell variable `name`; a program variable
    /// may only take a literal value, which is read as the program runs it.
    pub(super) fn var_set(&mut self, name: &str, how: &str, written: Written<'_>) -> W {
        if let Some(r) = cmds::program_var(name) {
            match written {
                Written::Kept => {}
                Written::Value(v) => self.program_var(name, r, Some(v), how)?,
                Written::Unknown => self.program_var(name, r, None, how)?,
            }
        }
        if name == "TOLLGATE_INLINE_CAP" {
            return Err(format!(
                "{how} writes TOLLGATE_INLINE_CAP; it may only be a number written in front of git or tollgate (G6)"
            ));
        }
        if let Some(why) = cmds::sensitive(name) {
            return Err(format!("{how} writes {name}, which {why} (G5)"));
        }
        if cmds::scoped(name).is_some() {
            self.scoped_writes.push((name.to_owned(), how.to_owned()));
        }
        if name == "PATH" {
            self.path_write(how, written)?;
        }
        // Unknown until a caller that knows the value sets it.
        self.scope.vars.insert(name.to_owned(), None);
        self.scope.ints.remove(name);
        self.log.push(name.to_owned());
        Ok(())
    }

    // ---- PATH (G1, G5, review G5 PATH) ---------------------------------

    /// A write of PATH through `how`: its value is unknown until a caller
    /// that knows the word sets [`Scope::path`]. `export PATH` and
    /// `readonly PATH` keep the value; `local PATH` and `declare PATH` in
    /// a function make an empty one, and `unset PATH` makes bash search
    /// the cwd.
    fn path_write(&mut self, how: &str, written: Written<'_>) -> W {
        if matches!(written, Written::Kept) && matches!(how, "export" | "readonly") {
            return Ok(());
        }
        if self.trap_lookups {
            return Err(format!(
                "{how} writes PATH after a trap that runs commands by name was set: the trap would run what the new PATH finds; set PATH before the trap (G1, G5)"
            ));
        }
        if how == "a nameref" {
            self.path_hidden = true;
        }
        self.path_writes += 1;
        self.scope.path = PathVal::Unknown;
        Ok(())
    }

    /// The PATH a bare command name is found on now.
    fn path_now(&self) -> PathVal {
        if self.path_hidden {
            PathVal::Unknown
        } else {
            self.scope.path.clone()
        }
    }

    /// The PATH an assignment of `w` to PATH gives (`+=` when `appends`):
    /// `$PATH` and `${PATH}` splice in the PATH that holds now, `~` and
    /// variables the guard knows expand; anything else is unknown.
    fn path_of(&self, w: Option<&Word>, appends: bool) -> PathVal {
        const MARK: &str = "\0PATH\0";
        let v = match w {
            None => String::new(),
            Some(w) => {
                let lookup = |n: &str| {
                    if n == "PATH" {
                        Some(MARK.to_owned())
                    } else {
                        self.lookup(n)
                    }
                };
                match w.value(&lookup, Some(&self.home)) {
                    Some(v) => v,
                    None => return PathVal::Unknown,
                }
            }
        };
        let text = if appends { format!("{MARK}{v}") } else { v };
        let mut segs = Vec::new();
        for s in text.split(':') {
            if s == MARK {
                match self.path_now() {
                    PathVal::Session => segs.push(None),
                    PathVal::Known(k) => segs.extend(k),
                    PathVal::Unknown => return PathVal::Unknown,
                }
            } else if s.contains('\0') {
                return PathVal::Unknown;
            } else {
                segs.push(Some(s.to_owned()));
            }
        }
        // A dir again later on PATH finds nothing new.
        let mut seen = BTreeSet::new();
        segs.retain(|s| seen.insert(s.clone()));
        if segs == [None] {
            PathVal::Session
        } else {
            PathVal::Known(segs)
        }
    }

    /// The PATH `env` gives its command with assignment `e`.
    fn env_path(&self, e: &EnvSet) -> PathVal {
        match &e.value {
            Some(v) => PathVal::Known(v.split(':').map(|s| Some(s.to_owned())).collect()),
            None => PathVal::Unknown,
        }
    }

    /// Runs `f` with `p` as the PATH, then puts the PATH back unless `f`
    /// changed it (then it is unknown).
    fn with_path(&mut self, p: Option<PathVal>, f: impl FnOnce(&mut Self) -> W) -> W {
        let Some(p) = p else {
            return f(self);
        };
        let saved = std::mem::replace(&mut self.scope.path, p.clone());
        let r = f(self);
        self.scope.path = if self.scope.path == p {
            saved
        } else {
            PathVal::Unknown
        };
        r
    }

    /// The files bare command name `name` may run from the dirs this
    /// command puts on PATH: each is checked as the program it is. A
    /// file the command writes there counts, and so does a link. The
    /// session's own dirs are the session's programs.
    fn path_hits(&self, name: &str) -> Result<Vec<String>, Deny> {
        let segs = match self.path_now() {
            PathVal::Session => return Ok(Vec::new()),
            PathVal::Unknown => {
                return Err(format!(
                    "`{name}` after this command sets PATH to a value the guard cannot follow: bash may find any program by that name; give the program's path, or set PATH to dirs written literally (`~`, $HOME, $PWD and $PATH expand) (G1, G5)"
                ));
            }
            PathVal::Known(segs) => segs,
        };
        let mut hits: Vec<String> = Vec::new();
        for dir in segs.iter().flatten() {
            let dir = if dir.is_empty() { "." } else { dir.as_str() };
            // bash expands a leading `~` when it searches; a program that
            // gets the value from `env` does not, and finds a dir `~`.
            let mut dirs = vec![dir.to_owned()];
            if let Some(rest) = dir.strip_prefix('~') {
                if !(rest.is_empty() || rest.starts_with('/')) {
                    return Err(format!(
                        "`{name}` after this command puts `{dir}` on PATH, a dir in another user's home; give the program's path (G1, G5)"
                    ));
                }
                dirs.push(format!("{}{rest}", self.home));
            }
            for d in dirs {
                let Some(p) = self.abs_path(&format!("{d}/{name}")) else {
                    return Err(format!(
                        "`{name}` with the relative dir `{d}` on PATH, in a cwd the guard cannot follow; give the program's path or an absolute dir (G1, G5, G8)"
                    ));
                };
                if !p.is_dir() && (p.exists() || p.is_symlink() || self.was_written(&p)) {
                    let p = p.to_string_lossy().into_owned();
                    if !hits.contains(&p) {
                        hits.push(p);
                    }
                }
            }
        }
        Ok(hits)
    }

    /// G1, G3 (review G5 PATH): `name` is a path to a text file named
    /// like a program the guard knows (`./fake/git`, `./fake/bash`): a
    /// shell script, or text bash runs as one, is read and checked as a
    /// script, not as that program. A script in another language named
    /// like git, tollgate, a shell or an interpreter (`strict`) denies;
    /// other programs may be scripts (`npx`, `parallel`) and keep their
    /// own checks.
    fn shell_script_named(&self, name: &str, base: &str, strict: bool) -> Result<bool, Deny> {
        let Some(p) = self.abs_path(name) else {
            return Err(format!(
                "{name} after a cd the guard cannot follow; use an absolute path (G3, G8)"
            ));
        };
        if p.is_dir() {
            return Ok(false);
        }
        let head = if self.was_written(&p) {
            match self.known.get(&p) {
                Some(t) => t.as_bytes().iter().take(256).copied().collect(),
                // path_command denies: the guard cannot see what runs.
                None => return Ok(true),
            }
        } else {
            match read_head(&p) {
                Ok(h) => h,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                Err(e) => {
                    return Err(format!(
                        "the guard reads {name} before it runs and cannot ({e}); run it in a later call (G3)"
                    ));
                }
            }
        };
        if is_binary(&head) {
            return Ok(false);
        }
        match shebang(&head) {
            None => Ok(true),
            Some(prog)
                if prog == "git"
                    || prog == "tollgate"
                    || matches!(cmds::classify(&prog), Class::Shell(_) | Class::Opaque(_)) =>
            {
                Ok(true)
            }
            Some(prog) if strict => Err(format!(
                "{name} is a `{prog}` script, not the program {base}; run it by its interpreter (G1, G3)"
            )),
            Some(_) => Ok(false),
        }
    }

    /// Item 21: program variable `name` (read as `r`) gets value `v`
    /// (`None`: one bash builds at run time) through `how`.
    fn program_var(&mut self, name: &str, r: cmds::Runs, v: Option<&str>, how: &str) -> W {
        let Some(v) = v else {
            return Err(format!(
                "{how} gives {name} a value bash builds at run time; a program runs that value, so give it literally (G3, item 21)"
            ));
        };
        let what = format!("{how}: {name}");
        let code = cmds::runs_code(r, v).map_err(|e| format!("{what}: {e} (G3, item 21)"))?;
        match code {
            Some(code) => self.program_code(&code, &what),
            None => Ok(()),
        }
    }

    /// Item 21: shell text a program runs from a value (a git config key,
    /// a variable, an option), checked as code with no stdin, none of
    /// this command's variables and an unknown cwd: git runs most of them
    /// from the top of the work tree, not from here, so a relative script
    /// or write in them denies (G8).
    pub(super) fn program_code(&mut self, code: &str, what: &str) -> W {
        let frame = Frame {
            stdin: Feed::Unknown,
            env: Vec::new(),
        };
        self.isolated(|w| {
            w.scope.cwd = Cwd::Unknown;
            w.code(code, true, &frame, what)
        })
    }

    /// Parses `text` as shell code and checks it (G3).
    pub(super) fn code(&mut self, text: &str, child: bool, f: &Frame, what: &str) -> W {
        if self.depth >= MAX_CODE_DEPTH {
            return Err(format!("{what}: code nested too deeply to check (G3)"));
        }
        let s = shell::parse(text)
            .map_err(|e| format!("{what}: the guard cannot parse this code ({e}) (G3)"))?;
        self.depth += 1;
        let r = if child {
            self.detached(|w| w.isolated(|w| w.script(&s, f)))
        } else {
            self.script(&s, f)
        };
        self.depth -= 1;
        r
    }

    // ---- G2: wrappers and launchers -------------------------------------

    fn wrapper(
        &mut self,
        name: &'static str,
        argv: &[Word],
        mut env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
        certain: bool,
    ) -> W {
        match name {
            "env" => return self.env_wrapper(argv, env, f, via, certain),
            "find" => return self.find(argv, &env, f),
            "parallel" => {
                self.env_check(&env, Target::Other)?;
                return self.launch_tokens("parallel", &argv[1..]);
            }
            _ => {}
        }
        let lits = self.lits(argv);
        let (spec, pre, no_run) = cmds::wrapper_opts(name);
        let (opts, first) = match cmds::parse_opts(&spec, &lits, 1) {
            Ok(r) => r,
            // `command -v $c`: an option that runs nothing comes before the
            // word bash builds.
            Err(_) if cmds::no_run_first(&spec, &lits, no_run) => {
                return self.env_check(&env, Target::Other);
            }
            Err(e) => {
                return Err(format!(
                    "{name}: {e}; write the wrapper's options literally (G2)"
                ));
            }
        };
        if opts.iter().any(|o| no_run.contains(&o.name.as_str())) {
            return self.env_check(&env, Target::Other);
        }
        let value = |o: &cmds::Opt| -> Option<Word> {
            match &o.value {
                Some(OptValue::Word(k)) => argv.get(*k).cloned(),
                Some(OptValue::Glued(t)) => Some(Word {
                    parts: vec![Part::Lit(t.clone())],
                    brace: false,
                    raw: t.clone(),
                }),
                None => None,
            }
        };
        // Option values that are code, files written or variables set.
        for o in &opts {
            match (name, o.name.as_str()) {
                ("exec", "-c" | "-a") => {
                    // bash finds the program on its own PATH, then runs
                    // it with the environment cleared (-c).
                    let what = "exec -c/-a (a changed environment or argv[0])";
                    self.launch_tokens(what, &argv[first..])?;
                    return match argv.get(first).and_then(|c| c.literal_home(&self.home)) {
                        Some(n) => self.launched_name(what, &n, &env, false),
                        None => Ok(()),
                    };
                }
                ("time", "-o" | "--output") => {
                    if let Some(w) = value(o) {
                        self.write_target(&w, false, "time -o")?;
                    }
                }
                ("xargs", "--process-slot-var") => {
                    let n = value(o).and_then(|w| w.literal()).unwrap_or_default();
                    self.var_write(&n, "xargs --process-slot-var")?;
                    env.push(EnvSet {
                        name: n.clone(),
                        value: None,
                        prefix: false,
                        raw: format!("--process-slot-var={n}"),
                    });
                }
                _ => {}
            }
        }
        // `flock FILE -c CODE` runs CODE with sh -c.
        if name == "flock"
            && matches!(
                lits.get(first + 1).cloned().flatten().as_deref(),
                Some("-c" | "--command")
            )
        {
            self.no_elsewhere(via, "flock -c")?;
            self.env_check(&env, Target::Code)?;
            let code = argv
                .get(first + 2)
                .and_then(Word::literal)
                .ok_or_else(|| "flock -c with code that is not a literal word (G3)".to_owned())?;
            let frame = Frame {
                stdin: f.stdin.clone(),
                env,
            };
            return self.code(&code, true, &frame, "flock -c");
        }
        let inner = first + pre;
        self.path_words(name, &argv[1..inner.min(argv.len())], &[], None)?;
        let via = if name == "xargs" { Via::Elsewhere } else { via };
        let Some(cmd) = argv.get(inner) else {
            // No command: xargs runs echo; the others run nothing (or fail).
            if via == Via::Elsewhere && name != "xargs" {
                return Err(format!(
                    "{name} under xargs or find -exec gets its command from elsewhere (G2)"
                ));
            }
            return self.env_check(&env, Target::Other);
        };
        let inner_name = self.command_word(cmd)?;
        self.run(&argv[inner..], &inner_name, env, f, via, certain)
    }

    fn env_wrapper(
        &mut self,
        argv: &[Word],
        mut env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
        certain: bool,
    ) -> W {
        const LONG: &[&str] = &[
            "ignore-environment",
            "null",
            "unset",
            "chdir",
            "split-string",
            "block-signal",
            "default-signal",
            "ignore-signal",
            "list-signal-handling",
            "debug",
            "argv0",
            "help",
            "version",
        ];
        let lits = self.lits(argv);
        let mut losing: Option<&str> = None;
        let mut chdir: Option<Word> = None;
        let mut i = 1;
        let bad = |what: &str| {
            format!("env: {what}; write env's options and assignments literally (G2, G5)")
        };
        while i < argv.len() {
            let Some(a) = lits[i].as_deref() else {
                return Err(bad(
                    "a word bash builds at run time where env reads options",
                ));
            };
            if a == "--" {
                i += 1;
                break;
            }
            if a == "-" {
                losing = Some("env -");
                i += 1;
                break;
            }
            if !a.starts_with('-') {
                break;
            }
            if let Some(long) = a.strip_prefix("--") {
                let (n, glued) = match long.split_once('=') {
                    Some((n, v)) => (n, Some(v)),
                    None => (long, None),
                };
                let hits: Vec<&&str> = LONG.iter().filter(|l| l.starts_with(n)).collect();
                let full = match (LONG.iter().find(|l| **l == n), hits.as_slice()) {
                    (Some(l), _) => *l,
                    (None, [one]) if !n.is_empty() => **one,
                    _ => return Err(bad(&format!("unknown or ambiguous option --{n}"))),
                };
                let takes = matches!(full, "unset" | "chdir" | "split-string" | "argv0");
                let value_word = if takes && glued.is_none() {
                    i += 1;
                    argv.get(i).cloned()
                } else {
                    glued.map(lit_word)
                };
                match full {
                    "ignore-environment" => losing = Some("env -i"),
                    "unset" => {
                        losing = Some("env -u");
                        self.env_unset(value_word.as_ref())?;
                    }
                    "split-string" => {
                        self.split_string(value_word.as_ref())?;
                        losing = Some("env -S");
                    }
                    "chdir" => chdir = value_word,
                    "help" | "version" | "list-signal-handling" => {
                        return self.env_check(&env, Target::Other);
                    }
                    _ => {}
                }
                i += 1;
                continue;
            }
            let cluster = &a[1..];
            let mut consumed_next = false;
            for (k, c) in cluster.char_indices() {
                let rest = &cluster[k + 1..];
                match c {
                    'i' => losing = Some("env -i"),
                    '0' | 'v' => {}
                    'u' | 'S' | 'C' | 'a' => {
                        let value_word = if rest.is_empty() {
                            consumed_next = true;
                            argv.get(i + 1).cloned()
                        } else {
                            Some(lit_word(rest))
                        };
                        match c {
                            'u' => {
                                losing = Some("env -u");
                                self.env_unset(value_word.as_ref())?;
                            }
                            'S' => {
                                self.split_string(value_word.as_ref())?;
                                losing = Some("env -S");
                            }
                            'C' => chdir = value_word,
                            _ => {}
                        }
                        break;
                    }
                    _ => return Err(bad(&format!("unknown option -{c}"))),
                }
            }
            i += if consumed_next { 2 } else { 1 };
        }
        // Assignments.
        let inherited = env.len();
        while i < argv.len() {
            let Some(a) = lits[i].as_deref() else {
                let (prefix, _) = argv[i].literal_prefix();
                if prefix.contains('=') {
                    let n = prefix.split('=').next().unwrap_or_default();
                    if shell::is_name(n.trim_end_matches('+')) {
                        let n = n.trim_end_matches('+');
                        if let Some(why) = cmds::sensitive(n) {
                            return Err(format!("`{}` sets {n}, which {why} (G5)", argv[i].raw));
                        }
                        env.push(EnvSet {
                            name: n.to_owned(),
                            value: None,
                            prefix: false,
                            raw: argv[i].raw.clone(),
                        });
                        i += 1;
                        continue;
                    }
                }
                break;
            };
            let Some((n, v)) = a.split_once('=') else {
                break;
            };
            let n = n.strip_suffix('+').unwrap_or(n);
            if !shell::is_name(n) {
                break;
            }
            env.push(EnvSet {
                name: n.to_owned(),
                value: Some(v.to_owned()),
                prefix: false,
                raw: a.to_owned(),
            });
            i += 1;
        }
        if let Some(what) = losing {
            self.env_check(&env, Target::Other)?;
            let what = format!(
                "{what} (it drops or replaces the session environment, the hook injection included)"
            );
            let clears = matches!(losing, Some("env -i" | "env -"));
            let check = |w: &mut Self| {
                w.launch_tokens(&what, &argv[i..])?;
                match argv.get(i).and_then(|c| c.literal_home(&w.home)) {
                    Some(name) => w.launched_name(&what, &name, &env, clears),
                    None => Ok(()),
                }
            };
            // `-C DIR`: paths in the command are relative to DIR.
            return match chdir {
                None => check(self),
                Some(d) => {
                    let dir = self.resolve(&d);
                    self.isolated(|w| {
                        w.scope.cwd = match dir.and_then(|t| w.abs_path(&t)) {
                            Some(p) => Cwd::Known(p),
                            None => Cwd::Unknown,
                        };
                        check(w)
                    })
                }
            };
        }
        let Some(cmd) = argv.get(i) else {
            if via == Via::Elsewhere {
                return Err(
                    "env under xargs or find -exec gets its command from elsewhere (G2)".into(),
                );
            }
            return self.env_check(&env, Target::Other);
        };
        let inner_name = self.command_word(cmd)?;
        // G1, G5: env finds its command on a PATH it is given.
        let path = env[inherited..]
            .iter()
            .rev()
            .find(|e| e.name == "PATH")
            .map(|e| self.env_path(e));
        match chdir {
            None => self.with_path(path, |w| {
                w.run(&argv[i..], &inner_name, env, f, via, certain)
            }),
            Some(d) => {
                let dir = self.resolve(&d);
                self.isolated(|w| {
                    w.scope.cwd = match dir.and_then(|t| w.abs_path(&t)) {
                        Some(p) => Cwd::Known(p),
                        None => Cwd::Unknown,
                    };
                    if let Some(p) = path {
                        w.scope.path = p;
                    }
                    w.run(&argv[i..], &inner_name, env, f, via, certain)
                })
            }
        }
    }

    fn env_unset(&mut self, w: Option<&Word>) -> W {
        let Some(n) = w.and_then(Word::literal) else {
            return Err("env -u with a name that is not literal (G5)".into());
        };
        if n == "TOLLGATE_INLINE_CAP" || cmds::sensitive(&n).is_some() {
            return self.var_write(&n, "env -u");
        }
        Ok(())
    }

    /// `env -S`: the string must be literal and use none of env's own
    /// escapes or variables (item 18).
    fn split_string(&self, w: Option<&Word>) -> W {
        match w.and_then(Word::literal) {
            // env reads PATH and -C from the string itself: a name found on
            // that PATH or a path relative to that dir is not what the
            // guard checks.
            Some(s)
                if s.replace(['\'', '"'], "").split_whitespace().any(|a| {
                    a.starts_with("PATH=")
                        || a.starts_with("--c")
                        || (a.starts_with('-') && !a.starts_with("--") && a.contains('C'))
                }) =>
            {
                Err(
                    "env -S with PATH= or -C in its string: give the program's path and run it from its dir (G2, G3)"
                        .into(),
                )
            }
            Some(s) if !s.contains(['\\', '$']) => {
                self.launch_tokens("env -S", &[lit_word(&s)])
            }
            _ => Err(
                "env -S with a string that is not literal or uses env's escapes or ${VAR}: the guard does not read env's own syntax (item 18, G2)"
                    .into(),
            ),
        }
    }

    /// G2 (item 40): runner `base` runs a command from its words with the
    /// session's environment ([`runners`]): the command is walked as if
    /// typed, with no git, tollgate or shell at any depth under it; when
    /// the runner's options are not known, every word is held to the
    /// launcher rule instead.
    #[allow(clippy::too_many_arguments)]
    fn runner(
        &mut self,
        base: &str,
        l: Launch,
        argv: &[Word],
        env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
        certain: bool,
    ) -> W {
        // Words from elsewhere may be the command (`xargs strace`).
        self.no_elsewhere(via, base)?;
        self.env_check(&env, Target::Other)?;
        let (at, prefix, moved) = match l {
            Launch::Deny(why) => return Err(why),
            Launch::Strict { from } => {
                self.path_words(base, &argv[1..], &env, Some(via))?;
                return self.launch_tokens(base, &argv[from..]);
            }
            Launch::Walk { at, prefix, moved } => (at, prefix, moved),
        };
        self.path_words(base, &argv[1..at.min(argv.len())], &[], None)?;
        let Some(cmd) = argv.get(at) else {
            return Ok(());
        };
        let word = self.command_word(cmd)?;
        if moved && word.contains('/') && !word.starts_with('/') {
            return Err(format!(
                "{base} changes the directory before it runs {word}; give the program's absolute path (G2, G8)"
            ));
        }
        let mut inner: Vec<Word> = prefix.iter().map(|p| lit_word(p)).collect();
        inner.extend_from_slice(&argv[at..]);
        let name = prefix.first().map_or(word, |p| (*p).to_owned());
        self.runner_depth += 1;
        let r = self.run(&inner, &name, env, f, via, certain);
        self.runner_depth -= 1;
        r
    }

    /// G2b: `what` runs `args` elsewhere or with another environment: no
    /// git, tollgate, shell or interpreter in them, all literal.
    pub(super) fn launch_tokens(&self, what: &str, args: &[Word]) -> W {
        for w in args {
            let Some(t) = w.literal_home(&self.home) else {
                return Err(format!(
                    "{what} with `{}`, a word bash builds at run time; write its arguments literally (G2)",
                    w.raw
                ));
            };
            if let Some(kind) =
                cmds::tokens(&t).find_map(|tok| cmds::forbidden(tok, super::git::KNOWN))
            {
                return Err(format!(
                    "{what} runs {kind} (`{t}`) where the guard cannot follow it; run it directly in the session (G2)"
                ));
            }
            for tok in cmds::tokens(&t).filter(|tok| tok.contains('/')) {
                self.launched_file(what, tok, false)?;
            }
        }
        Ok(())
    }

    /// G2, G3 (item 20, review note 9): `text`, a path in what a launcher
    /// runs, may not be a script: the launcher runs it unread (a shell or
    /// an interpreter), and an environment-dropping one runs the git in
    /// it without the hook injection. A file this command writes first is
    /// unknown, so it is denied too; a binary runs (21d). `command` is true
    /// when `text` is in the program's place (the command word of `env`
    /// or `exec` with their environment options): any text file there is
    /// a script (execvp runs a file with no `#!` with sh, and a mode
    /// change the guard does not see can make it executable). Elsewhere a
    /// word may be data (`sudo cat /etc/hosts`), so a text file counts
    /// when it is executable, starts with `#!`, or this command changes
    /// its mode.
    fn launched_file(&self, what: &str, text: &str, command: bool) -> W {
        use std::os::unix::fs::PermissionsExt as _;
        let Some(p) = self.abs_path(text) else {
            return Err(format!(
                "{what} with {text} after a cd the guard cannot follow; use an absolute path (G2, G8)"
            ));
        };
        if self.was_written(&p) {
            return Err(format!(
                "{what} with {text}, which this command writes first; the guard cannot read what runs there (G2, G3)"
            ));
        }
        // Not there or not a file: nothing runs it as a program.
        let Ok(meta) = std::fs::metadata(&p) else {
            return Ok(());
        };
        if !meta.is_file() {
            return Ok(());
        }
        let exec =
            meta.permissions().mode() & 0o111 != 0 || self.moded.iter().any(|m| p.starts_with(m));
        let head = match read_head(&p) {
            Ok(h) => h,
            Err(_) if !command && !exec => return Ok(()),
            Err(e) => {
                return Err(format!(
                    "{what} with {text}, a program the guard cannot read ({e}) (G2, G3)"
                ));
            }
        };
        if is_binary(&head) || !(command || exec || head.starts_with(b"#!")) {
            return Ok(());
        }
        Err(format!(
            "{what} runs the script {text} where the guard cannot read it, and git in it may run without the gate hooks; run the script directly in the session (G2, G3)"
        ))
    }

    /// G2, G3: a bare command name under a launcher that drops or
    /// replaces the environment, found on a `PATH` this command sets (in
    /// `env`'s assignments, in front, or earlier in the shell): every
    /// match is checked as [`Self::launched_file`]. `clears` is true when
    /// the launcher starts from an empty environment (`env -i`, `env -`),
    /// so only a `PATH` it is given applies.
    fn launched_name(&self, what: &str, name: &str, env: &[EnvSet], clears: bool) -> W {
        if name.contains('/') {
            return self.launched_file(what, name, true);
        }
        let path = match env.iter().rev().find(|e| e.name == "PATH") {
            Some(e) => e.value.clone().ok_or_else(|| {
                format!(
                    "{what} with `{}`, a PATH bash builds at run time; give the program's path (G2, G3)",
                    e.raw
                )
            })?,
            None if clears => return Ok(()),
            None if self.scope.opaque || self.scope.vars.contains_key("PATH") => {
                return Err(format!(
                    "{what} {name} after this command changes PATH; give the program's path (G2, G3)"
                ));
            }
            None => return Ok(()),
        };
        for dir in path.split(':') {
            let dir = if dir.is_empty() { "." } else { dir };
            self.launched_file(what, &format!("{dir}/{name}"), true)?;
            if let Some(rest) = dir.strip_prefix('~') {
                self.launched_file(what, &format!("{}{rest}/{name}", self.home), true)?;
            }
        }
        Ok(())
    }

    fn launcher(&mut self, l: &str, argv: &[Word], env: Vec<EnvSet>, f: &Frame, via: Via) -> W {
        self.no_elsewhere(via, l)?;
        self.env_check(&env, Target::Other)?;
        let args = &argv[1..];
        let lits: Vec<String> = self.lits(args).into_iter().flatten().collect();
        let has = |o: &str| lits.iter().any(|a| a == o);
        let cluster_has = |c: char| {
            lits.iter()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a[1..].contains(c))
        };
        // docker and podman launch only with run and exec.
        if matches!(l, "docker" | "podman") && !(has("run") || has("exec")) {
            return self.launch_tokens_quiet(l, args);
        }
        self.launch_tokens(l, args)?;
        let shell_why = match l {
            "sudo" if cluster_has('s') || cluster_has('i') || has("--shell") || has("--login") => {
                Some("sudo -s/-i starts a shell")
            }
            "doas" if cluster_has('s') => Some("doas -s starts a shell"),
            "su" if !(cluster_has('c')
                || lits
                    .iter()
                    .any(|a| a.starts_with("--command") || a.starts_with("--session-command"))) =>
            {
                Some("su without -c starts a shell")
            }
            "runuser"
                if !(cluster_has('u')
                    || has("--user")
                    || cluster_has('c')
                    || lits.iter().any(|a| a.starts_with("--command"))) =>
            {
                Some("runuser without -u or -c starts a shell")
            }
            "pkexec" if lits.iter().all(|a| a.starts_with('-')) => {
                Some("pkexec without a program starts a shell")
            }
            "systemd-run" if cluster_has('S') || has("--shell") => {
                Some("systemd-run --shell starts a shell")
            }
            "machinectl" if has("shell") || has("login") => Some("machinectl shell starts a shell"),
            "ssh" if ssh_without_command(&lits) => {
                Some("ssh without a remote command starts a shell")
            }
            "script" if !(cluster_has('c') || lits.iter().any(|a| a.starts_with("--command"))) => {
                Some("script without -c starts a shell")
            }
            "tmux"
                if lits.iter().any(|a| {
                    matches!(
                        a.as_str(),
                        "send-keys"
                            | "send"
                            | "paste-buffer"
                            | "pasteb"
                            | "load-buffer"
                            | "loadb"
                            | "set-buffer"
                            | "setb"
                    )
                }) =>
            {
                Some("tmux send-keys and buffers type text into a shell")
            }
            "screen" if has("stuff") => Some("screen -X stuff types text into a shell"),
            "kitty" | "kitten" if has("send-text") || has("send-key") => {
                Some("kitty @ send-text types text into a shell")
            }
            "at" | "batch" => match self.stdin(f) {
                _ if cluster_has('f') => Some("at -f reads its commands from a file"),
                Feed::Tty => None,
                Feed::Doc(Some(body)) => {
                    return self.launch_tokens(l, &[lit_word(&body)]);
                }
                _ => Some(
                    "at and batch read their commands from a pipe or file the guard cannot read",
                ),
            },
            "nsenter" | "unshare" | "chroot" | "firejail" if self.stdin(f) != Feed::Tty => {
                Some("it may start a shell that reads its stdin")
            }
            // Item 40: they type text into a session or window, which may
            // be a shell or a TTY-only prompt.
            "dtach" if cluster_has('p') => Some("dtach -p types its stdin into a session"),
            "empty" if cluster_has('s') => Some("empty -s types text into a session"),
            "zellij"
                if lits.iter().any(|a| {
                    matches!(a.as_str(), "write-chars" | "write" | "send-keys" | "paste")
                }) =>
            {
                Some("zellij action write types text into a pane")
            }
            "qdbus" | "qdbus6" | "qdbus-qt6" | "gdbus" | "dbus-send" | "busctl"
                if lits.iter().any(|a| {
                    let a = a.to_ascii_lowercase();
                    a.contains("runcommand") || a.contains("sendtext")
                }) =>
            {
                Some("it types text into a terminal session")
            }
            "wtype" | "dotool" | "dotoolc" => {
                Some("it types text into the window that has focus, which may be a shell")
            }
            "ydotool" | "xdotool"
                if lits
                    .iter()
                    .any(|a| matches!(a.as_str(), "type" | "key" | "keydown" | "keyup")) =>
            {
                Some("it types text into the window that has focus, which may be a shell")
            }
            "dtach" | "abduco" | "empty" | "faketty" | "fakeroot" | "fakechroot" | "proot"
            | "newgrp" | "sg" | "run0" | "capsh" | "schroot" | "systemd-nspawn" | "lxc-attach"
            | "toolbox" | "distrobox" | "distrobox-enter" | "dbus-run-session" | "zellij"
            | "rlwrap"
                if self.stdin(f) != Feed::Tty =>
            {
                Some("it may start a shell or a session that reads its stdin")
            }
            _ => None,
        };
        if let Some(why) = shell_why {
            return Err(format!(
                "{l}: {why}, which the guard cannot follow; run the commands directly (G2)"
            ));
        }
        Ok(())
    }

    /// Non-launching docker/podman commands: only literal-word checks.
    fn launch_tokens_quiet(&self, _l: &str, _args: &[Word]) -> W {
        Ok(())
    }

    // ---- G3: shells, scripts, interpreters --------------------------------

    /// G3 (item 21/20, review G2): a shell or script host whose language
    /// the guard does not read may run any command from its code, so it
    /// runs only to print its version or help, interactively on the
    /// session's stdin, or (`osascript`) with notification and dialog code.
    fn opaque(&mut self, o: &str, argv: &[Word], env: Vec<EnvSet>, f: &Frame, via: Via) -> W {
        self.no_elsewhere(via, o)?;
        self.env_check(&env, Target::Code)?;
        let lits = self.lits(&argv[1..]);
        match lits.as_slice() {
            [] if self.stdin(f) == Feed::Tty => return Ok(()),
            [Some(a)]
                if matches!(
                    a.as_str(),
                    "--version" | "-version" | "-v" | "-V" | "--help" | "-help" | "-h"
                ) =>
            {
                return Ok(());
            }
            _ => {}
        }
        if o == "osascript" {
            return osascript_ok(&lits);
        }
        Err(format!(
            "{o} runs code in a language the guard does not read, and that code may run git or tollgate; run the commands in bash directly (G3, item 21/20)"
        ))
    }

    fn shell(&mut self, sh: &str, argv: &[Word], env: Vec<EnvSet>, f: &Frame, via: Via) -> W {
        self.no_elsewhere(via, sh)?;
        self.env_check(&env, Target::Code)?;
        let lits = self.lits(argv);
        let foreign = matches!(sh, "zsh" | "fish" | "csh" | "tcsh" | "yash");
        let mut has_c = false;
        let mut from_stdin = false;
        // `-n` (noexec): the shell reads the code and runs none of it, so
        // not even a `set +n` in it. An interactive shell ignores it.
        let mut noexec = false;
        let mut interactive = false;
        let mut code_word: Option<Word> = None;
        let mut i = 1;
        while i < argv.len() {
            let Some(a) = lits[i].as_deref() else {
                return Err(format!(
                    "{sh}: `{}` is a word bash builds at run time where the shell reads options (G3)",
                    argv[i].raw
                ));
            };
            if a == "--" || a == "-" {
                i += 1;
                break;
            }
            if let Some(long) = a.strip_prefix("--") {
                match long {
                    "no-execute" if sh == "fish" => noexec = true,
                    "interactive" => interactive = true,
                    "norc" | "noprofile" | "login" | "posix" | "noediting" | "restricted"
                    | "verbose" | "no-execute" | "no-config" | "private" => {}
                    "rcfile" | "init-file" => i += 1,
                    "help" | "version" => return Ok(()),
                    l if sh == "fish" && (l == "command" || l.starts_with("command=")) => {
                        has_c = true;
                        if let Some(v) = l.strip_prefix("command=") {
                            code_word = Some(lit_word(v));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "{sh}: unknown option --{long}; the guard knows only the common shell options (G3)"
                        ));
                    }
                }
                i += 1;
                continue;
            }
            if (a.starts_with('-') || a.starts_with('+')) && a.len() > 1 {
                let on = a.starts_with('-');
                for c in a[1..].chars() {
                    match c {
                        'c' => has_c = true,
                        's' => from_stdin = true,
                        // The last of `-n`, `+n`, `-o noexec`, `+o noexec`
                        // holds.
                        'n' => noexec = on,
                        'i' => interactive |= on,
                        'o' => {
                            i += 1;
                            if lits.get(i).is_some_and(|o| o.as_deref() == Some("noexec")) {
                                noexec = on;
                            }
                        }
                        'O' => i += 1,
                        'C' if sh == "fish" => {
                            return Err(
                                "fish -C runs init code the guard does not read (G3)".into()
                            );
                        }
                        _ => {}
                    }
                }
                i += 1;
                continue;
            }
            break;
        }
        if noexec && !interactive {
            return Ok(());
        }
        let frame = Frame {
            stdin: f.stdin.clone(),
            env,
        };
        if has_c {
            let w = match code_word {
                Some(w) => w,
                None => argv
                    .get(i)
                    .cloned()
                    .ok_or_else(|| format!("{sh} -c without code"))?,
            };
            let code = w.literal().ok_or_else(|| {
                format!(
                    "{sh} -c with code that is not a literal word (`{}`): the guard checks only code it can read (G3)",
                    w.raw
                )
            })?;
            if foreign {
                foreign_shell_ok(sh, &code)?;
            }
            return self.code(&code, true, &frame, &format!("{sh} -c"));
        }
        if !from_stdin && let Some(file) = argv.get(i) {
            return self.script_file(file, true, frame.env, f, sh);
        }
        match self.stdin(f) {
            Feed::Tty => Ok(()),
            Feed::Doc(Some(body)) => {
                if foreign {
                    foreign_shell_ok(sh, &body)?;
                }
                self.code(&body, true, &frame, &format!("the heredoc read by {sh}"))
            }
            Feed::Doc(None) => Err(format!(
                "{sh} reads a heredoc with expansions; quote the delimiter (<<'EOF') or run the commands directly (G3)"
            )),
            _ => Err(format!(
                "{sh} reads its program from a pipe or a file the guard cannot read; run the commands directly (G3)"
            )),
        }
    }

    /// A shell or `source` runs script file `w` (G3): read it (one level,
    /// at most 1 MiB) and check it.
    fn script_file(&mut self, w: &Word, child: bool, env: Vec<EnvSet>, f: &Frame, who: &str) -> W {
        if w.parts.iter().any(|p| matches!(p, Part::ProcSub(_))) {
            return Err(format!(
                "{who} runs a process substitution as its script; the guard cannot read it (G3, item 40)"
            ));
        }
        let Some(text) = w.literal_home(&self.home) else {
            return Err(format!(
                "{who} runs `{}`, a script path bash builds at run time; give the path literally (G3)",
                w.raw
            ));
        };
        if text.starts_with("/dev/") || text.starts_with("/proc/") {
            return Err(format!(
                "{who} reads its script from {text}, which the guard cannot read (G3)"
            ));
        }
        // Item 21/20: under a program the guard does not know, a shell
        // word may be data (`cargo test bash -- --nocapture`). A script
        // that is not there, is a dir, and is not on the PATH runs nothing.
        if !self.foreign.is_empty() && self.runs_nothing(&text, &env) {
            return Ok(());
        }
        let path = if text.contains('/') {
            self.abs_path(&text)
        } else {
            match self.abs_path(&text) {
                Some(p) if p.is_file() || self.was_written(&p) => Some(p),
                _ => {
                    return Err(format!(
                        "{who} {text}: not a file in the cwd, so bash would search PATH; give the path (./{text}) (G3)"
                    ));
                }
            }
        };
        let Some(path) = path else {
            return Err(format!(
                "{who} runs {text} after a cd the guard cannot follow; use an absolute path (G3, G8)"
            ));
        };
        let frame = Frame {
            stdin: f.stdin.clone(),
            env,
        };
        self.read_and_walk(&path, child, &frame)
    }

    /// True when a shell given script `text` finds nothing to run (item
    /// 21/20): not a file or written in this command, and, for a bare
    /// name, on no dir of the session's `PATH`, which this command does
    /// not change.
    fn runs_nothing(&self, text: &str, env: &[EnvSet]) -> bool {
        let Some(p) = self.abs_path(text) else {
            return false;
        };
        if self.was_written(&p) || p.is_file() || p.is_symlink() {
            return false;
        }
        if text.contains('/') {
            return true;
        }
        if self.scope.opaque
            || self.scope.vars.contains_key("PATH")
            || env.iter().any(|e| e.name == "PATH")
        {
            return false;
        }
        let Some(path) = std::env::var_os("PATH") else {
            return false;
        };
        // The session's shell may add dirs its profile sets: the usual
        // ones count too.
        let home = PathBuf::from(&self.home);
        let usual = [
            home.join(".local/bin"),
            home.join("bin"),
            home.join(".cargo/bin"),
            home.join(".bun/bin"),
            PathBuf::from("/usr/local/bin"),
            PathBuf::from("/usr/local/sbin"),
            PathBuf::from("/opt/homebrew/bin"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/sbin"),
        ];
        !std::env::split_paths(&path).chain(usual).any(|d| {
            let c = if d.as_os_str().is_empty() {
                self.abs_path(".").map(|d| d.join(text))
            } else if d.is_absolute() {
                Some(d.join(text))
            } else {
                None
            };
            // A relative dir resolves against a cwd the guard may not
            // follow: count it as a match.
            c.is_none_or(|c| c.exists() || c.is_symlink())
        })
    }

    /// True when this command writes `p`, or a dir above it, before now.
    pub(super) fn was_written(&self, p: &Path) -> bool {
        self.written.iter().any(|w| p.starts_with(w))
    }

    /// True when this command writes, removes or replaces `p` (absolute),
    /// a dir above it or anything under it before now (G7, item 22,
    /// secreview note 7: a link or repo it makes).
    pub(super) fn changes(&self, p: &Path) -> bool {
        let c = paths::canon(p);
        self.written
            .iter()
            .any(|w| p.starts_with(w) || w.starts_with(p) || c.starts_with(w) || w.starts_with(&c))
    }

    /// The text of `p`, which this command writes first: known only when a
    /// literal heredoc wrote it whole, once.
    fn known_text(&self, p: &Path, shown: &str) -> Result<String, Deny> {
        self.known.get(p).cloned().ok_or_else(|| {
            format!(
                "{shown} is written earlier in this command; the guard reads a script before the command runs, so run it in a later call or write it with cat > FILE <<'EOF' (G3)"
            )
        })
    }

    fn read_and_walk(&mut self, path: &Path, child: bool, f: &Frame) -> W {
        let shown = path.display();
        if self.in_script {
            return Err(format!(
                "{shown} is run from a script file; the guard reads script files one level deep (G3)"
            ));
        }
        let text = if self.was_written(path) {
            self.known_text(path, &shown.to_string())?
        } else {
            let meta = std::fs::metadata(path).map_err(|e| {
                format!("the guard reads {shown} before it runs and cannot ({e}); run it in a later call (G3)")
            })?;
            if !meta.is_file() {
                return Err(format!("{shown} is not a regular file (G3)"));
            }
            if meta.len() > MAX_SCRIPT {
                return Err(format!(
                    "{shown} is larger than 1 MiB; the guard reads scripts up to 1 MiB (G3)"
                ));
            }
            let bytes =
                std::fs::read(path).map_err(|e| format!("cannot read {shown}: {e} (G3)"))?;
            String::from_utf8(bytes)
                .map_err(|_| format!("{shown} is not UTF-8 text; the guard cannot check it (G3)"))?
        };
        self.tollgate_named |= paths::spells_tollgate_dir(self.ctx, &text);
        self.claude_named |= paths::spells_claude(self.ctx, &text);
        let s = shell::parse(&text)
            .map_err(|e| format!("the guard cannot parse the script {shown} ({e}) (G3)"))?;
        if self.depth >= MAX_CODE_DEPTH {
            return Err(format!("{shown}: code nested too deeply to check (G3)"));
        }
        self.depth += 1;
        self.in_script = true;
        let r = if child {
            self.detached(|w| w.isolated(|w| w.script(&s, f)))
        } else {
            // A `return` in a sourced file ends it there: the values then
            // reach the code after the `.` as well.
            self.returns.push(Vec::new());
            let r = self.script(&s, f);
            for j in self.returns.pop().unwrap_or_default() {
                self.scope.merge(&j);
            }
            r
        };
        self.in_script = false;
        self.depth -= 1;
        r
    }

    /// A command named by a path (`./x.sh`, `/abs/tool`): a shell script
    /// is read and checked (G3); a binary or another interpreter's script
    /// runs as it is.
    fn path_command(
        &mut self,
        name: &str,
        base: &str,
        argv: &[Word],
        env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
    ) -> W {
        let Some(p) = self.abs_path(name) else {
            return Err(format!(
                "{name} after a cd the guard cannot follow; use an absolute path (G3, G8)"
            ));
        };
        let head = if self.was_written(&p) {
            self.known_text(&p, name)?.into_bytes()
        } else {
            let head = read_head(&p).map_err(|e| {
                format!("the guard reads {name} before it runs and cannot ({e}); run it in a later call (G3)")
            })?;
            if p.is_dir() {
                return Ok(());
            }
            head
        };
        if is_binary(&head) {
            return self.other(name, base, argv, &env, f, via);
        }
        // A script gets its arguments as `$1`...: it is no reader.
        self.path_words(name, &argv[1..], &env, Some(via))?;
        let interp = shebang(&head);
        match interp.as_deref() {
            Some(prog) if cmds::interp(prog).is_some() => {
                self.no_elsewhere(via, name)?;
                self.env_check(&env, Target::Other)
            }
            Some(prog) if prog == "git" || prog == "tollgate" => Err(format!(
                "{name} runs {prog} as its interpreter; the guard does not allow it (G3)"
            )),
            Some(prog) if matches!(cmds::classify(prog), Class::Opaque(_)) => Err(format!(
                "{name} runs {prog} as its interpreter, a language the guard does not read (G3, item 21/20)"
            )),
            Some(prog) if !matches!(cmds::classify(prog), Class::Shell(_)) => {
                self.other(name, base, argv, &env, f, via)
            }
            // A shell script, or text with no `#!` (bash runs it as one).
            _ => {
                self.no_elsewhere(via, name)?;
                self.env_check(&env, Target::Code)?;
                let frame = Frame {
                    stdin: f.stdin.clone(),
                    env,
                };
                self.read_and_walk(&p, true, &frame)
            }
        }
    }

    fn interp(
        &mut self,
        lang: Lang,
        base: &str,
        argv: &[Word],
        env: Vec<EnvSet>,
        f: &Frame,
        via: Via,
    ) -> W {
        self.no_elsewhere(via, base)?;
        self.env_check(&env, Target::Other)?;
        let values: Vec<Option<String>> = argv.iter().map(|w| self.arg_value(w)).collect();
        self.foreign_args(argv, &values, &env, f, via)?;
        let lits = self.lits(argv);
        // In-place edits write the files they read: `perl -pi`, `ruby
        // -pi`, `gawk -i inplace` (R25, R26, G7).
        let in_place = match lang {
            Lang::Perl | Lang::Ruby => write_targets("perl", argv, &lits),
            Lang::Awk => awk_in_place(argv, &lits),
            _ => Vec::new(),
        };
        for (w, removal) in in_place {
            self.write_target(&w, removal, base)?;
        }
        let prog = interp_program(lang, &lits, argv)?;
        match prog {
            Program::Inline(code) => {
                self.config_names(base, &code);
                if let Some(why) = cmds::spawns(lang, &code) {
                    return Err(format!(
                        "{base} inline code with {why}, which can start git or a shell where the guard cannot see it; put the code in a file or drop the process call (G3)"
                    ));
                }
                Ok(())
            }
            Program::File(files) => self.program_files(lang, base, argv, &files),
            Program::None => Ok(()),
            Program::Stdin => match self.stdin(f) {
                Feed::Tty => Ok(()),
                Feed::Doc(Some(body)) => {
                    self.config_names(base, &body);
                    match cmds::spawns(lang, &body) {
                        Some(why) => Err(format!(
                            "{base} reads a program with {why} from a heredoc; the guard does not allow process calls there (G3)"
                        )),
                        None => Ok(()),
                    }
                }
                _ => Err(format!(
                    "{base} reads its program from a pipe or a file the guard cannot read (G3)"
                )),
            },
        }
    }

    /// R26, G7 (item 21 review): interpreter code the guard reads that
    /// names Claude Code settings or git's global config may write them,
    /// and the guard does not follow file calls in code: a person
    /// decides. A raw-text match, so a read asks too.
    fn config_names(&mut self, base: &str, code: &str) {
        if let Some(what) = paths::config_named(self.ctx, &code.to_lowercase()) {
            self.ask(format!(
                "{base} code names {what}, which it may write; those files decide what every later session and git command runs, so a person decides (R26, G7)"
            ));
        }
    }

    /// G3: an interpreter runs its program file unread, so the file may
    /// not be one this command writes first (the guard would never see
    /// what runs). A path the guard cannot resolve counts as one when the
    /// command writes any file before it.
    fn program_files(&mut self, lang: Lang, base: &str, argv: &[Word], files: &[ProgArg]) -> W {
        for f in files {
            let text = match f {
                ProgArg::Text(t) => Some(t.clone()),
                ProgArg::Word(k) => argv.get(*k).and_then(|w| self.resolve(w)),
            };
            let shown = text.clone().unwrap_or_else(|| match f {
                ProgArg::Word(k) => argv.get(*k).map(|w| w.raw.clone()).unwrap_or_default(),
                ProgArg::Text(t) => t.clone(),
            });
            match text.as_deref().and_then(|t| self.abs_path(t)) {
                Some(p) if self.was_written(&p) => {
                    // Written whole from a literal heredoc: checked as
                    // inline code.
                    let code = self.known.get(&p).cloned().ok_or_else(|| {
                        format!(
                            "{base} runs {}, which this command writes first; the guard reads such a program only when cat > FILE <<'EOF' writes it whole, so write it that way or run it in a later call (G3)",
                            p.display()
                        )
                    })?;
                    self.config_names(base, &code);
                    if let Some(why) = cmds::spawns(lang, &code) {
                        return Err(format!(
                            "{base} runs {} with {why}, written earlier in this command, which can start git or a shell where the guard cannot see it; drop the process call or run it in a later call (G3)",
                            p.display()
                        ));
                    }
                }
                Some(_) => {}
                None if self.written.is_empty() => {}
                None => {
                    return Err(format!(
                        "{base} runs `{shown}`, a program path the guard cannot resolve, after this command writes files; give the path literally (G3)"
                    ));
                }
            }
        }
        Ok(())
    }

    // ---- G5: variable writers --------------------------------------------

    fn var_writer(&mut self, b: &str, argv: &[Word], env: &[EnvSet]) -> W {
        self.env_check(env, Target::Other)?;
        let lits = self.lits(argv);
        let nonlit = |w: &Word| {
            format!(
                "{b} with `{}`, a variable name bash builds at run time (G5)",
                w.raw
            )
        };
        match b {
            "export" | "declare" | "typeset" | "local" | "readonly" => {
                let mut funcs = false;
                let mut nameref = false;
                // `-n`, not `+n` (which drops the attribute).
                let mut sets_nameref = false;
                let mut options = true;
                for (k, w) in argv.iter().enumerate().skip(1) {
                    let (prefix, full) = w.literal_prefix();
                    if options && full && prefix == "--" {
                        options = false;
                        continue;
                    }
                    if options
                        && full
                        && (prefix.starts_with('-') || prefix.starts_with('+'))
                        && prefix.len() > 1
                    {
                        funcs |= prefix.contains('f') || prefix.contains('F');
                        nameref |= prefix.contains('n') && b != "export";
                        sets_nameref |=
                            prefix.starts_with('-') && prefix.contains('n') && b != "export";
                        if prefix.starts_with('-') && prefix.contains('i') && b != "export" {
                            return Err(format!(
                                "{b} {prefix}: the integer attribute makes every later assignment arithmetic, which can run code from a value (G3)"
                            ));
                        }
                        continue;
                    }
                    options = false;
                    if funcs {
                        continue;
                    }
                    let (name, value) = match prefix.split_once('=') {
                        Some((n, _)) => (n.trim_end_matches('+').to_owned(), Some(w)),
                        None if full => (prefix.clone(), None),
                        None => return Err(nonlit(w)),
                    };
                    let name = self.name_ref(&name, b)?.to_owned();
                    let v = value
                        .and_then(|w| shell::split_assign(w).and_then(|(_, v)| self.resolve(&v)));
                    let written = match (value, v.as_deref()) {
                        (None, _) => Written::Kept,
                        (Some(_), Some(v)) if !prefix.contains("+=") && !prefix.contains('[') => {
                            Written::Value(v)
                        }
                        _ => Written::Unknown,
                    };
                    // G1, G5: the PATH bare names are found on from here.
                    let path =
                        (name == "PATH" && value.is_some() && !prefix.contains('[')).then(|| {
                            let v = value.and_then(|w| shell::split_assign(w).map(|(_, v)| v));
                            match v {
                                Some(v) => self.path_of(Some(&v), prefix.contains("+=")),
                                None => PathVal::Unknown,
                            }
                        });
                    self.var_set(&name, b, written)?;
                    if name == "PATH" && nameref {
                        self.path_hidden = true;
                    }
                    if let Some(p) = path
                        && !self.path_hidden
                    {
                        self.scope.path = p;
                    }
                    if nameref {
                        // `declare -n ref=NAME`: writes through ref reach
                        // NAME, and bash evaluates a subscript in NAME
                        // wherever ref is used (G3).
                        let target = lits[k]
                            .as_deref()
                            .and_then(|l| l.split_once('=').map(|(_, t)| t.to_owned()));
                        match target {
                            Some(t) => {
                                let t = self.name_ref(&t, &format!("{b} -n target"))?;
                                self.var_write(t, "a nameref")?;
                            }
                            None if value.is_some() => return Err(nonlit(w)),
                            // `declare -n ref` takes ref's value, or the
                            // next one assigned to it, as the target.
                            None if sets_nameref => {
                                return Err(format!(
                                    "{b} -n {name} without a target: bash takes the value ref has or gets next as the name, and evaluates a subscript in it (G3)"
                                ));
                            }
                            None => {}
                        }
                        if sets_nameref {
                            self.namerefs.insert(name.clone());
                            self.nameref_loops()?;
                        }
                        // Writes through the reference change another
                        // variable from here on.
                        self.scope.forget();
                        self.log.push("*".into());
                    }
                    if value.is_some() || !self.scope.vars.contains_key(&name) {
                        self.scope.vars.insert(name, v);
                    }
                }
                Ok(())
            }
            "unset" => {
                let mut funcs = false;
                for (k, w) in argv.iter().enumerate().skip(1) {
                    let Some(a) = lits[k].as_deref() else {
                        return Err(nonlit(w));
                    };
                    if a.starts_with('-') {
                        funcs |= a.contains('f');
                        continue;
                    }
                    if !funcs {
                        let n = self.name_ref(a, "unset")?;
                        self.var_set(n, "unset", Written::Kept)?;
                        let v = (n == a).then(String::new);
                        self.scope.vars.insert(n.to_owned(), v);
                    }
                }
                Ok(())
            }
            "read" => {
                let mut k = 1;
                while k < argv.len() {
                    let Some(a) = lits[k].as_deref() else {
                        return Err(nonlit(&argv[k]));
                    };
                    if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
                        for (j, c) in cluster.char_indices() {
                            if "adinNptu".contains(c) {
                                let rest = &cluster[j + 1..];
                                let v = if rest.is_empty() {
                                    k += 1;
                                    lits.get(k).cloned().flatten()
                                } else {
                                    Some(rest.to_owned())
                                };
                                if c == 'a' {
                                    let v =
                                        v.ok_or_else(|| nonlit(&argv[k.min(argv.len() - 1)]))?;
                                    let n = self.name_ref(&v, "read -a")?;
                                    self.var_write(n, "read -a")?;
                                }
                                break;
                            }
                        }
                        k += 1;
                        continue;
                    }
                    let n = self.name_ref(a, "read")?;
                    self.var_write(n, "read")?;
                    self.scope.vars.insert(n.to_owned(), None);
                    k += 1;
                }
                Ok(())
            }
            "mapfile" | "readarray" => {
                let mut k = 1;
                while k < argv.len() {
                    let Some(a) = lits[k].as_deref() else {
                        return Err(nonlit(&argv[k]));
                    };
                    if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
                        if cluster.contains('C') {
                            return Err(format!(
                                "{b} -C runs a callback the guard does not read (G3)"
                            ));
                        }
                        if cluster.ends_with(['d', 'n', 'O', 's', 'u', 'c']) && cluster.len() == 1 {
                            k += 1;
                        }
                        k += 1;
                        continue;
                    }
                    let n = self.name_ref(a, b)?;
                    self.var_write(n, b)?;
                    k += 1;
                }
                Ok(())
            }
            "printf" => {
                match lits.get(1).cloned().flatten().as_deref() {
                    Some("-v") => {
                        let n = lits.get(2).cloned().flatten().ok_or_else(|| {
                            argv.get(2)
                                .map_or_else(|| "printf -v without a name".to_owned(), nonlit)
                        })?;
                        let n = self.name_ref(&n, "printf -v")?;
                        self.var_write(n, "printf -v")?;
                    }
                    Some(v) if v.starts_with("-v") && v.len() > 2 => {
                        let n = self.name_ref(&v[2..], "printf -v")?;
                        self.var_write(n, "printf -v")?;
                    }
                    None if argv.len() > 1 && argv[1].literal_prefix().0.starts_with("-v") => {
                        return Err(nonlit(&argv[1]));
                    }
                    _ => {}
                }
                Ok(())
            }
            "getopts" => {
                if let Some(w) = argv.get(2) {
                    let n = w.literal().ok_or_else(|| nonlit(w))?;
                    let n = self.name_ref(&n, "getopts")?;
                    self.var_write(n, "getopts")?;
                }
                Ok(())
            }
            "wait" => {
                // `wait -p NAME` stores a process id in NAME.
                let mut k = 1;
                while k < argv.len() {
                    let Some(a) = lits[k].as_deref() else {
                        return Err(nonlit(&argv[k]));
                    };
                    if a == "--" || !a.starts_with('-') || a.len() < 2 {
                        break;
                    }
                    if let Some(j) = a.find('p') {
                        let rest = &a[j + 1..];
                        let v = if rest.is_empty() {
                            k += 1;
                            let w = argv.get(k).ok_or("wait -p without a name")?;
                            lits[k].clone().ok_or_else(|| nonlit(w))?
                        } else {
                            rest.to_owned()
                        };
                        let n = self.name_ref(&v, "wait -p")?;
                        self.var_write(n, "wait -p")?;
                    }
                    k += 1;
                }
                Ok(())
            }
            "let" => {
                for w in &argv[1..] {
                    let text = self.arg_value(w).ok_or_else(|| {
                        format!(
                            "let `{}`: bash evaluates text it builds at run time as arithmetic, which can run code (G3)",
                            w.raw
                        )
                    })?;
                    if text.contains('`') || text.contains("$(") {
                        return Err(format!(
                            "let `{text}`: bash evaluates it as arithmetic, and code in it runs (G3)"
                        ));
                    }
                    self.arith_names(&text)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    // ---- G8: cwd ---------------------------------------------------------

    fn cd(&mut self, b: &str, argv: &[Word], certain: bool) -> W {
        let lits = self.lits(argv);
        let mut i = 1;
        while let Some(Some(a)) = lits.get(i) {
            if a == "--" {
                i += 1;
                break;
            }
            if a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| "LPe@n".contains(c)) {
                i += 1;
                continue;
            }
            break;
        }
        let arg = argv.get(i);
        let old = self.scope.cwd.clone();
        match b {
            "popd" => {
                if arg.is_some() {
                    self.scope.cwd = Cwd::Unknown;
                } else {
                    self.scope.cwd = self.scope.stack.pop().unwrap_or(Cwd::Unknown);
                }
            }
            "pushd" if arg.is_none() => {
                // Swaps the top two dirs.
                match self.scope.stack.pop() {
                    Some(top) => {
                        self.scope.stack.push(old.clone());
                        self.scope.cwd = top;
                    }
                    None => self.scope.cwd = Cwd::Unknown,
                }
            }
            _ => {
                // Review G7/R25: the guard must know when the cwd is one
                // of tollgate's dirs.
                if let Some(w) = arg
                    && self.resolve(w).is_none()
                    && paths::spells_tollgate_tail(self.ctx, &w.raw)
                {
                    return Err(format!(
                        "{b} to `{}`, a dir bash builds at run time that names /tollgate; write it literally (R25, G7, G8)",
                        w.raw
                    ));
                }
                let target = match arg {
                    None => Some(self.home.clone()),
                    Some(w) => match w.literal().as_deref() {
                        Some("-") if b == "cd" => match &self.scope.oldpwd {
                            Cwd::Known(p) => Some(p.to_string_lossy().into_owned()),
                            Cwd::Unknown => None,
                        },
                        Some(t) if b == "pushd" && (t.starts_with('+') || t.starts_with('-')) => {
                            None
                        }
                        _ => self.resolve(w),
                    },
                };
                if b == "pushd" {
                    self.scope.stack.push(old.clone());
                }
                self.change_dir(target, certain);
            }
        }
        self.scope.oldpwd = old;
        self.log.push(".".into());
        Ok(())
    }

    fn change_dir(&mut self, target: Option<String>, certain: bool) {
        let cdpath = self.lookup("CDPATH").is_some_and(|v| !v.is_empty());
        let new = target.and_then(|t| {
            let relative = !t.starts_with('/')
                && !t.starts_with("./")
                && !t.starts_with("../")
                && t != "."
                && t != "..";
            if cdpath && relative {
                return None;
            }
            self.abs_path(&t)
        });
        self.scope.cwd = match new {
            None => Cwd::Unknown,
            // bash's cd fails on a dir it cannot search, and the shell
            // stays where it was.
            Some(p) if p.is_dir() && searchable(&p) => Cwd::Known(p),
            Some(p) if certain => {
                // Created earlier in this command, or the list stops here.
                self.cd_uncertain = true;
                Cwd::Known(p)
            }
            Some(_) => Cwd::Unknown,
        };
    }

    // ---- paths -----------------------------------------------------------

    /// A variable's value: literal ones set in this command, then the
    /// session environment (`PWD` is the tracked cwd).
    fn lookup(&self, name: &str) -> Option<String> {
        if let Some(v) = self.scope.vars.get(name) {
            return v.clone();
        }
        if self.scope.opaque {
            return None;
        }
        if name == "PWD" {
            return match &self.scope.cwd {
                Cwd::Known(p) => Some(p.to_string_lossy().into_owned()),
                Cwd::Unknown => None,
            };
        }
        self.ctx.var(name).map(str::to_owned)
    }

    /// A word's value with simple variables and `~` resolved.
    pub(super) fn resolve(&self, w: &Word) -> Option<String> {
        if self.ifs_set() && w.parts.iter().any(|p| matches!(p, Part::Param(..))) {
            return None;
        }
        w.value(&|n| self.lookup(n), Some(&self.home))
    }

    /// `text` as an absolute, canonical path; `None` when it is relative
    /// and the cwd is unknown.
    pub(super) fn abs_path(&self, text: &str) -> Option<PathBuf> {
        // `canon` applies `..` to the dir a link resolves to, as the
        // kernel does (`lnk/../hooks`); a lexical `..` first would drop
        // the link.
        let p = Path::new(text);
        if p.is_absolute() {
            return Some(paths::canon(p));
        }
        match &self.scope.cwd {
            Cwd::Known(c) => Some(paths::canon(&c.join(p))),
            Cwd::Unknown => None,
        }
    }

    /// `text` as an absolute path with `.` and `..` applied but no
    /// symlink resolved; `None` when it is relative and the cwd is
    /// unknown.
    fn lexical_path(&self, text: &str) -> Option<PathBuf> {
        let p = Path::new(text);
        if p.is_absolute() {
            return Some(paths::lexical(Path::new("/"), p));
        }
        match &self.scope.cwd {
            Cwd::Known(c) => Some(paths::lexical(c, p)),
            Cwd::Unknown => None,
        }
    }

    /// R25, G7, G8: a file the command writes or removes.
    pub(super) fn write_target(&mut self, w: &Word, removal: bool, how: &str) -> W {
        let Some(text) = self.resolve(w) else {
            return Err(format!(
                "{how} writes to `{}`, a path the guard cannot resolve; write the path literally (G8)",
                w.raw
            ));
        };
        let Some(p) = self.abs_path(&text) else {
            return Err(format!(
                "{how} writes to the relative path `{text}` after a cd the guard cannot follow; use an absolute path (G8)"
            ));
        };
        if let Some(d) = paths::tollgate_dir(self.ctx, &p, removal) {
            return Err(format!(
                "writes to tollgate's dir {} (R25); reads are allowed",
                d.display()
            ));
        }
        if let Some(what) = paths::git_internal(&p) {
            return Err(format!(
                "{how} writes into {what} ({}); refs, remote config and hooks change only through git commands the guard checks (G7)",
                p.display()
            ));
        }
        // R26: Claude Code settings register the guard and the hook
        // injection; a write, move, link, mode change or removal of them
        // asks, as Write/Edit does. The path as spelled counts too: a
        // link to the settings dir resolves away from its name.
        if !matches!(how, "touch" | "mkdir" | "setfattr")
            && let Some(s) = paths::claude_settings(self.ctx, &p).or_else(|| {
                self.lexical_path(&text)
                    .and_then(|l| paths::claude_settings(self.ctx, &l))
            })
        {
            self.ask(paths::settings_write_reason(how, &s));
        }
        // Item 35, review note 12: a tool the job PATH finds, a toolchain,
        // registry source or host tool config changes what every later
        // job runs. A removal alone puts nothing there; a mode change can
        // make a file run.
        let leaves_text = matches!(how, "touch" | "mkdir" | "setfattr" | "chown" | "chgrp");
        let only_removes = removal && how != "mv";
        if !leaves_text
            && !only_removes
            && let Some(t) = paths::tool_path(self.ctx, &p)
        {
            let why = paths::tool_write_reason(how, &p, t);
            self.ask(why);
        }
        // Modes, owners, attributes, times and new dirs leave the text of
        // every file as it was.
        if !matches!(
            how,
            "chmod" | "chown" | "chgrp" | "setfattr" | "touch" | "mkdir"
        ) {
            if let Some(f) = paths::git_global_config(self.ctx, &p) {
                return Err(format!(
                    "{how} writes git's config file {}, whose program keys every git command runs; set keys with git config, which the guard checks (G7, item 21)",
                    f.display()
                ));
            }
            self.known.remove(&p);
            self.written.push(p);
        } else if matches!(how, "chmod" | "chown" | "chgrp") {
            self.moded.push(p);
        }
        Ok(())
    }

    /// The tollgate dir that text `v` (an argument or environment value)
    /// names as a path, and that path; see [`paths::path_candidates`].
    fn names_tollgate_dir(&self, v: &str) -> Option<(PathBuf, PathBuf)> {
        // Kept per cwd and value: each word of an unknown program is
        // checked again as a command with the words after it (L19).
        let cwd = match &self.scope.cwd {
            Cwd::Known(c) => Some(c.clone()),
            Cwd::Unknown => None,
        };
        let key = (cwd, v.to_owned());
        if let Some(r) = self.value_memo.borrow().get(&key) {
            return r.clone();
        }
        let r = paths::path_candidates(v, &self.home)
            .iter()
            .find_map(|c| self.candidate_reach(c));
        self.value_memo.borrow_mut().insert(key, r.clone());
        r
    }

    /// [`Self::names_tollgate_dir`] for one candidate path.
    /// Results are kept per path for the call: a word list repeats paths
    /// (L19: 100 words of an unknown program are each checked as a
    /// command with the words after it).
    fn candidate_reach(&self, c: &str) -> Option<(PathBuf, PathBuf)> {
        let l = self.lexical_path(c)?;
        let spelled = c.contains('/') || c.starts_with(['.', '~']);
        // The path as written, from the cwd: the key holds the cwd.
        let key = match &self.scope.cwd {
            Cwd::Known(cwd) => (cwd.join(c), spelled),
            Cwd::Unknown => (PathBuf::from(c), spelled),
        };
        if let Some(r) = self.reach_memo.borrow().get(&key) {
            return r.clone();
        }
        let p = self.canon_cached(&key.0)?;
        let r = paths::reaches_tollgate_dir(self.ctx, &p, spelled)
            .map(|d| (p, d.clone()))
            // The path as spelled too: `canon` keeps a link's name when
            // the link dangles.
            .or_else(|| {
                paths::reaches_tollgate_dir(self.ctx, &l, spelled).map(|d| (l.clone(), d.clone()))
            });
        self.reach_memo.borrow_mut().insert(key, r.clone());
        r
    }

    /// [`paths::canon`] of absolute `raw` (`None`: relative), with the
    /// real path of its dir kept for the call (L19: most words are names
    /// in the cwd, whose real path is known): one `lstat` of the last
    /// name, and the full resolution only when it is a link or `raw` has
    /// `..`.
    fn canon_cached(&self, raw: &Path) -> Option<PathBuf> {
        if !raw.is_absolute() {
            return None;
        }
        let dotted = raw.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        });
        let (Some(dir), Some(name), false) = (raw.parent(), raw.file_name(), dotted) else {
            return Some(paths::canon(raw));
        };
        let real_dir = match &self.scope.cwd {
            Cwd::Known(c) if c == dir => c.clone(),
            _ => {
                let hit = self.dir_memo.borrow().get(dir).cloned();
                hit.unwrap_or_else(|| {
                    let r = paths::canon(dir);
                    self.dir_memo.borrow_mut().insert(dir.to_owned(), r.clone());
                    r
                })
            }
        };
        let full = real_dir.join(name);
        match std::fs::symlink_metadata(&full) {
            Ok(m) if m.file_type().is_symlink() => Some(paths::canon(&full)),
            _ => Some(full),
        }
    }

    /// Review G7/R25: what word `w` names, as bash expands it: its value
    /// when the guard knows it, else its brace lists, `$'...'` text and
    /// globs (against the file system) when no part is only known at run
    /// time ([`reach`]).
    fn word_reach(&self, w: &Word) -> Reach {
        if let Some(v) = self.arg_value(w) {
            return self
                .names_tollgate_dir(&v)
                .map_or(Reach::Clear, |(p, d)| Reach::Hit(p, d));
        }
        let lookup = |n: &str| self.lookup(n);
        let Some(toks) = reach::tokens(w, &self.home, &lookup) else {
            return Reach::Unknown;
        };
        let Some(all) = reach::braces(&toks) else {
            return Reach::TooMany;
        };
        let cwd = match &self.scope.cwd {
            Cwd::Known(c) => Some(c.as_path()),
            Cwd::Unknown => None,
        };
        for t in all {
            for c in paths::path_candidates(&reach::text(&t), &self.home) {
                if reach::has_glob(&c) {
                    match reach::glob_reach(self.ctx, cwd, &c) {
                        Ok(Some((p, d))) => return Reach::Hit(p, d),
                        Ok(None) => {}
                        Err(()) => return Reach::TooMany,
                    }
                } else if let Some((p, d)) = self.candidate_reach(&c) {
                    return Reach::Hit(p, d);
                }
            }
        }
        if cwd.is_none() {
            return Reach::Unknown;
        }
        Reach::Clear
    }

    /// Review G7/R25: a program that is not a known reader may write any
    /// path it is given, in place (`curl -o`, `sort -o`, `tar -C`, `cc
    /// -o`, `cargo install --root`, `git init`), and the installed copy and
    /// every hook are one inode, so no list of writers is enough. `what`
    /// with `words` (its arguments, or a launcher's whole command) and
    /// `env` denies when a word, an option's value, a glued `-oVALUE`, an
    /// environment value or a variable this command set names a path in
    /// tollgate's state, data or config dir (or one of them lies under it),
    /// when a word bash builds at run time spells `/tollgate`, and when it
    /// runs in one of those dirs (`curl -O`, `tar -x` and `git init` write
    /// their cwd).
    ///
    /// `leaf` (how the program is run) is `None` for a wrapper's or
    /// runner's own options: the command it runs is checked as typed, with
    /// the cwd and variables. When the call spells one of tollgate's dirs
    /// anywhere ([`paths::spells_tollgate_dir`]), a value the guard cannot
    /// know may be such a path (`ls DIR | xargs sort -o`, `for f in
    /// DIR/*; do curl -o "$f" ...; done`): a word or environment value bash
    /// builds at run time, arguments from xargs or find, and an unknown
    /// cwd deny too.
    pub(super) fn tollgate_dir_words(
        &self,
        what: &str,
        words: &[Word],
        env: &[EnvSet],
        leaf: Option<Via>,
    ) -> W {
        if leaf.is_some() && self.tail_checked(words) {
            return Ok(());
        }
        let named = self.tollgate_named;
        let unknown = |shown: &str| {
            Err(format!(
                "`{what}` gets {shown}, which the guard cannot know, in a command that names tollgate's dirs; it is not a known reader (cat, grep, ls, ...), so it may write there; write the paths literally (R25, G7, G8)"
            ))
        };
        if named && leaf == Some(Via::Elsewhere) {
            return unknown("arguments from xargs, parallel or find");
        }
        if named && leaf.is_some() && matches!(self.scope.cwd, Cwd::Unknown) {
            return unknown("a cwd");
        }
        let leaf = leaf.is_some();
        let deny = |shown: &str, d: &Path| {
            Err(format!(
                "`{what}` is given {shown} in tollgate's dir {}, and it is not a known reader (cat, head, tail, grep, rg, jq, ls, stat, wc, diff, ...); a program may write any path it is given (R25, G7)",
                d.display()
            ))
        };
        if leaf && let Cwd::Known(c) = &self.scope.cwd {
            if let Some(d) = paths::tollgate_dir(self.ctx, c, false) {
                return Err(format!(
                    "`{what}` runs in tollgate's dir {}, where only known readers (cat, ls, grep, ...) run; a program may write its cwd (R25, G7)",
                    d.display()
                ));
            }
            if let Some(d) = paths::above_tollgate_dir(self.ctx, c) {
                return Err(format!(
                    "`{what}` runs in {}, above tollgate's dir {}, where only known readers (cat, ls, grep, ...) run; a program may write its cwd (R25, G7)",
                    c.display(),
                    d.display()
                ));
            }
        }
        let built = |raw: &str| paths::spells_tollgate_tail(self.ctx, raw);
        for w in words {
            match self.word_reach(w) {
                Reach::Hit(p, d) => return deny(&format!("the path {}", p.display()), &d),
                Reach::Clear => {}
                Reach::TooMany => {
                    return Err(format!(
                        "`{what}` is given `{}`, whose brace lists or globs give too many paths for the guard to check against tollgate's dirs (R25, G7, G8)",
                        w.raw
                    ));
                }
                Reach::Unknown if built(&w.raw) => {
                    return Err(format!(
                        "`{what}` is given `{}`, a word bash builds at run time that names /tollgate; write paths in tollgate's dirs literally, and only to readers (R25, G7, G8)",
                        w.raw
                    ));
                }
                Reach::Unknown if named && leaf => return unknown(&format!("`{}`", w.raw)),
                Reach::Unknown => {}
            }
        }
        for e in env {
            // `NAME=~/x` has no literal value; bash expands the `~`.
            let v = e.value.clone().or_else(|| {
                let (_, t) = e.raw.split_once('=')?;
                (!t.contains(['$', '`', '"', '\'', '\\'])).then(|| t.to_owned())
            });
            match v {
                Some(v) => {
                    if let Some((p, d)) = self.names_tollgate_dir(&v) {
                        return deny(
                            &format!("{} = {} in its environment", e.name, p.display()),
                            &d,
                        );
                    }
                }
                None if built(&e.raw) => {
                    return Err(format!(
                        "`{what}` gets `{}`, a value bash builds at run time that names /tollgate (R25, G7, G8)",
                        e.raw
                    ));
                }
                None if named && leaf => return unknown(&format!("`{}`", e.raw)),
                None => {}
            }
        }
        if !leaf {
            return Ok(());
        }
        // `export`, `set -a` and `declare -x` hand a variable to every
        // later program; the guard does not track which ones are exported.
        let mut vars: Vec<(&String, &String)> = self
            .scope
            .vars
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
            .collect();
        vars.sort();
        for (name, v) in vars {
            if let Some((p, d)) = self.names_tollgate_dir(v) {
                return Err(format!(
                    "`{what}` runs while variable {name} = {} names tollgate's dir {}, and a program may write a path from its environment; unset {name} first, or use the path only with readers (cat, ls, grep, ...) (R25, G7)",
                    p.display(),
                    d.display()
                ));
            }
        }
        Ok(())
    }

    /// L19: `words` are the tail of an unknown program's words already
    /// checked with this cwd (each word is checked again as a command
    /// with the words after it).
    fn tail_checked(&self, words: &[Word]) -> bool {
        self.checked_tails.iter().any(|(cwd, raws)| {
            *cwd == self.scope.cwd
                && raws.len() >= words.len()
                && raws[raws.len() - words.len()..]
                    .iter()
                    .zip(words)
                    .all(|(r, w)| *r == w.raw)
        })
    }

    /// The words of a program that is not a known reader, which may write
    /// any path it is given: R25 for tollgate's dirs (deny,
    /// [`Self::tollgate_dir_words`]), then R26 for Claude Code settings
    /// (ask, [`Self::settings_words`]).
    pub(super) fn path_words(
        &self,
        what: &str,
        words: &[Word],
        env: &[EnvSet],
        leaf: Option<Via>,
    ) -> W {
        if leaf.is_some() && self.tail_checked(words) {
            return Ok(());
        }
        self.tollgate_dir_words(what, words, env, leaf)?;
        if let Some(why) = self.settings_words(what, words, env, leaf.is_some()) {
            self.ask(why);
        }
        Ok(())
    }

    /// R26 (review of item 21): the Claude Code settings files register
    /// the guard and the hook injection for every later session, and a
    /// program that is not a known reader may write any path it is given
    /// (`setpriv cp x ~/.claude/settings.json`, `systemd-run --user rm
    /// ...`, `tmux new -d ...`, `python3 w.py ~/.claude/settings.json`), as
    /// R25 has it for tollgate's dirs. The ask reason when a word, an
    /// option's value, a glob or brace result, an environment value or (for
    /// the program itself, `leaf`) a variable this command set names a
    /// settings path ([`paths::claude_settings_word`]), when a word bash
    /// builds at run time spells a settings name, or when the program runs
    /// in a settings dir.
    fn settings_words(
        &self,
        what: &str,
        words: &[Word],
        env: &[EnvSet],
        leaf: bool,
    ) -> Option<String> {
        // They make a dir, an empty file or an attribute, never settings
        // text (as `write_target` has it).
        if matches!(basename(what), "mkdir" | "touch" | "setfattr") {
            return None;
        }
        let given = |shown: String| {
            Some(format!(
                "`{what}` is given {shown}, Claude Code settings, which register the guard and the hook injection for every later session; it is not a known reader (cat, grep, jq, ls, ...), and a program may write any path it is given, so a person decides (R26)"
            ))
        };
        match &self.scope.cwd {
            Cwd::Known(c) if leaf && paths::claude_settings_dir(self.ctx, c) => {
                return Some(format!(
                    "`{what}` runs in {}, a Claude Code settings dir, and it is not a known reader (cat, grep, ls, ...); a program may write its cwd, so a person decides (R26)",
                    c.display()
                ));
            }
            Cwd::Unknown if leaf && self.claude_named => {
                return Some(format!(
                    "`{what}` runs in a cwd the guard cannot know, in a command that names Claude Code settings; it is not a known reader (cat, grep, ls, ...), and a program may write its cwd, so a person decides (R26)"
                ));
            }
            _ => {}
        }
        let built = |raw: &str| self.claude_named || paths::spells_claude(self.ctx, raw);
        for w in words {
            match self.settings_reach(w) {
                SettingsReach::Hit(p) => return given(format!("the path {}", p.display())),
                SettingsReach::TooMany => {
                    return given(format!(
                        "`{}`, whose brace lists or globs give too many paths to check against",
                        w.raw
                    ));
                }
                SettingsReach::Unknown if built(&w.raw) => {
                    return given(format!(
                        "`{}`, a word bash builds at run time that may name",
                        w.raw
                    ));
                }
                SettingsReach::Unknown | SettingsReach::Clear => {}
            }
        }
        for e in env {
            let v = e.value.clone().or_else(|| {
                let (_, t) = e.raw.split_once('=')?;
                (!t.contains(['$', '`', '"', '\'', '\\'])).then(|| t.to_owned())
            });
            match v {
                Some(v) => {
                    if let Some(p) = self.settings_value(&v) {
                        return given(format!("{} = {} in its environment", e.name, p.display()));
                    }
                }
                None if built(&e.raw) => {
                    return given(format!(
                        "`{}`, a value bash builds at run time that may name",
                        e.raw
                    ));
                }
                None => {}
            }
        }
        if !leaf {
            return None;
        }
        let mut vars: Vec<(&String, &String)> = self
            .scope
            .vars
            .iter()
            .filter_map(|(k, v)| v.as_ref().map(|v| (k, v)))
            .collect();
        vars.sort();
        vars.into_iter().find_map(|(name, v)| {
            self.settings_value(v).map(|p| {
                format!(
                    "`{what}` runs while variable {name} = {} names Claude Code settings, which register the guard and the hook injection for every later session; a program may write a path from its environment, so a person decides (R26)",
                    p.display()
                )
            })
        })
    }

    /// [`Self::settings_words`] for one word: the settings path it names.
    fn settings_reach(&self, w: &Word) -> SettingsReach {
        if let Some(v) = self.arg_value(w) {
            return self
                .settings_value(&v)
                .map_or(SettingsReach::Clear, SettingsReach::Hit);
        }
        let lookup = |n: &str| self.lookup(n);
        let Some(toks) = reach::tokens(w, &self.home, &lookup) else {
            return SettingsReach::Unknown;
        };
        let Some(all) = reach::braces(&toks) else {
            return SettingsReach::TooMany;
        };
        let cwd = match &self.scope.cwd {
            Cwd::Known(c) => Some(c.as_path()),
            Cwd::Unknown => None,
        };
        for t in all {
            for c in paths::path_candidates(&reach::text(&t), &self.home) {
                if reach::has_glob(&c) {
                    match reach::glob_claude(self.ctx, cwd, &c) {
                        Ok(Some(p)) => return SettingsReach::Hit(p),
                        Ok(None) => {}
                        Err(()) => return SettingsReach::TooMany,
                    }
                } else if let Some(p) = self.settings_candidate(&c) {
                    return SettingsReach::Hit(p);
                }
            }
        }
        if cwd.is_none() {
            return SettingsReach::Unknown;
        }
        SettingsReach::Clear
    }

    /// The settings path a literal value names (its path candidates).
    fn settings_value(&self, v: &str) -> Option<PathBuf> {
        paths::path_candidates(v, &self.home)
            .iter()
            .find_map(|c| self.settings_candidate(c))
    }

    /// [`paths::claude_settings_word`] for one candidate path, resolved
    /// and as spelled (a link to the settings dir resolves away from its
    /// name), kept for the call.
    fn settings_candidate(&self, c: &str) -> Option<PathBuf> {
        let l = self.lexical_path(c)?;
        let spelled = c.contains('/') || c.starts_with(['.', '~']);
        let key = match &self.scope.cwd {
            Cwd::Known(cwd) => (cwd.join(c), spelled),
            Cwd::Unknown => (PathBuf::from(c), spelled),
        };
        if let Some(r) = self.settings_memo.borrow().get(&key) {
            return r.clone();
        }
        let r = self
            .canon_cached(&key.0)
            .filter(|p| paths::claude_settings_word(self.ctx, p))
            .or_else(|| paths::claude_settings_word(self.ctx, &l).then_some(l));
        self.settings_memo.borrow_mut().insert(key, r.clone());
        r
    }

    /// Review G7/R25: `name` is a known reader ([`TOLLGATE_DIR_READERS`])
    /// as the system has it: found on the session's `PATH` (no `PATH` set
    /// in the command), or named by its path in `/usr/bin` or `/bin`.
    fn tollgate_reader(&self, name: &str, base: &str, env: &[EnvSet]) -> bool {
        if !TOLLGATE_DIR_READERS.contains(&base) {
            return false;
        }
        if name.contains('/') {
            return ["/usr/bin/", "/bin/"]
                .iter()
                .any(|d| name.strip_prefix(d).is_some_and(|n| !n.contains('/')));
        }
        !self.scope.vars.contains_key("PATH") && !env.iter().any(|e| e.name == "PATH")
    }

    /// After `cat > FILE <<'EOF'` ran: FILE holds the heredoc's text, when
    /// this is the only write of FILE so far and `cat` is the real one.
    fn note_known(&mut self, sc: &Simple, redirs: &[Redir], stdin: &Feed) {
        let Feed::Doc(Some(body)) = stdin else {
            return;
        };
        if sc.words.len() != 1
            || !sc.assigns.is_empty()
            || sc.words[0].literal().as_deref() != Some("cat")
            || self.scope.funcs.contains("cat")
            || self.scope.opaque
            || self.scope.vars.contains_key("PATH")
        {
            return;
        }
        let outs: Vec<&Redir> = redirs.iter().filter(|r| r.writes_file()).collect();
        let [r] = outs.as_slice() else {
            return;
        };
        if !matches!(r.op, Op::Out | Op::Clobber) || r.fd.is_some_and(|fd| fd != 1) {
            return;
        }
        let Some(p) = self.resolve(&r.target).and_then(|t| self.abs_path(&t)) else {
            return;
        };
        if self.written.iter().filter(|w| **w == p).count() == 1
            && !self.written.iter().any(|w| *w != p && p.starts_with(w))
        {
            self.known.insert(p, body.clone());
        }
    }

    fn other(
        &mut self,
        name: &str,
        base: &str,
        argv: &[Word],
        env: &[EnvSet],
        f: &Frame,
        via: Via,
    ) -> W {
        self.env_check(env, Target::Other)?;
        let lits = self.lits(argv);
        let function = self.scope.funcs.contains(name);
        if function {
            // A function gets its arguments as `$1`...: it is no reader.
            self.path_words(name, &argv[1..], env, Some(via))?;
            // G1, G5 (review G5 PATH): its body found its commands on the
            // PATH that held where it was defined.
            if let Some(p) = self.func_paths.get(name)
                && (*p == PathVal::Unknown || *p != self.path_now())
            {
                return Err(format!(
                    "`{name}` runs commands by name, and PATH changed after it was defined: it would run what the new PATH finds; define it after PATH is set (G1, G5)"
                ));
            }
            // Checked where it was defined; it may change the cwd and any
            // variable.
            self.scope.forget();
            self.log.push("*".into());
            if self.path_funcs.contains(name) {
                self.scope.path = PathVal::Unknown;
                self.log.push("PATH".into());
            }
            return Ok(());
        }
        let reader = self.tollgate_reader(name, base, env);
        if reader && !self.tollgate_named {
            // What a reader lists or prints may feed a later command
            // (`ls LINK | xargs ...`), also through a link that does not
            // spell the dir.
            self.tollgate_named = argv[1..]
                .iter()
                .any(|w| matches!(self.word_reach(w), Reach::Hit(..)));
        }
        // sed, sort and uniq write files their words name: from xargs,
        // parallel or find, those words are not seen.
        let parsed_writer = matches!(base, "sed" | "sort" | "uniq");
        let mut all_checked = false;
        if !reader || (parsed_writer && via == Via::Elsewhere) {
            // The files `cp` and `install` copy from are read; where they
            // write is checked here and by `write_target`.
            let sources = copy_sources(base, argv, &lits);
            let words: Vec<Word> = argv
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(k, _)| !sources.contains(k))
                .map(|(_, w)| w.clone())
                .collect();
            self.path_words(name, &words, env, Some(via))?;
            all_checked = sources.is_empty();
        }
        match base {
            "alias"
                if lits[1..]
                    .iter()
                    .any(|a| a.as_ref().is_none_or(|a| a.contains('='))) =>
            {
                return Err("alias definitions change what a command name runs; the guard does not allow them (G1)".into());
            }
            "hash"
                if lits[1..].iter().any(|a| {
                    a.as_ref().is_none_or(|a| {
                        a.starts_with("-p") || (a.starts_with('-') && a.contains('p'))
                    })
                }) =>
            {
                return Err("hash -p binds a command name to another program (G1)".into());
            }
            "enable"
                if lits[1..].iter().any(|a| {
                    a.as_ref()
                        .is_none_or(|a| a.starts_with('-') && a.contains('f'))
                }) =>
            {
                return Err("enable -f loads a builtin the guard does not know (G1)".into());
            }
            // Review G5 PATH: a builtin turned off is found on PATH.
            "enable"
                if lits[1..]
                    .iter()
                    .flatten()
                    .any(|a| a.starts_with('-') && a.contains('n')) =>
            {
                return Err(
                    "enable -n turns a builtin off, so its name runs a program found on PATH (G1)"
                        .into(),
                );
            }
            "trap" => return self.trap(argv, &lits),
            "watch" => return self.launch_tokens("watch", &argv[1..]),
            "rm" | "mv" => {
                let lock = lits[1..].iter().flatten().any(|a| {
                    let a = a.replace('\\', "/");
                    a.ends_with(".lock") && (a.contains("/.git/") || a.starts_with(".git/"))
                });
                if lock {
                    self.ask(format!(
                        "{base} of a git lock file: a live git may hold it; check with tollgate doctor --repo . (R26, R39)"
                    ));
                }
            }
            _ => {}
        }
        let values: Vec<Option<String>> = argv.iter().map(|w| self.arg_value(w)).collect();
        if !READS_ONLY.contains(&base) {
            // Review G7/R25 (L19): a command walked from these words gets a
            // tail of them, with this cwd and environment, all checked.
            if all_checked {
                let raws = argv[1..].iter().map(|w| w.raw.clone()).collect();
                self.checked_tails.push((self.scope.cwd.clone(), raws));
            }
            let r = self.foreign_args(argv, &values, env, f, via);
            if all_checked {
                self.checked_tails.pop();
            }
            r?;
        }
        let fx = super::progs::check(base, &values)?;
        for file in &fx.sed_files {
            for w in self.sed_file(file)? {
                self.write_target(&lit_word(&w), false, "a sed `w` command")?;
            }
        }
        for w in &fx.writes {
            self.write_target(&lit_word(w), false, "a sed `w` command")?;
        }
        for (w, removal) in write_targets(base, argv, &lits) {
            if via == Via::Elsewhere && w.literal().as_deref() == Some("{}") {
                // Review G7/R25: in a call that names tollgate's dirs,
                // `{}` may be a path there.
                if self.tollgate_named {
                    return Err(format!(
                        "{base} writes `{{}}`, a path from xargs, parallel or find, in a command that names tollgate's dirs (R25, G7)"
                    ));
                }
                continue;
            }
            self.write_target(&w, removal, base)?;
        }
        Ok(())
    }

    /// A word's value for [`super::progs::check`]: literal, or built from
    /// variables this command set and arithmetic (`$((n+30))`, always a
    /// number; `0` stands for it).
    fn arg_value(&self, w: &Word) -> Option<String> {
        if let Some(l) = w.literal_home(&self.home) {
            return Some(l);
        }
        let arith_free = |p: &Part| matches!(p, Part::Arith(_, subs) if subs.is_empty());
        let swap = |p: &Part| -> Part {
            match p {
                Part::Arith(_, subs) if subs.is_empty() => Part::Lit("0".into()),
                Part::Double(inner) => Part::Double(
                    inner
                        .iter()
                        .map(|q| {
                            if arith_free(q) {
                                Part::Lit("0".into())
                            } else {
                                q.clone()
                            }
                        })
                        .collect(),
                ),
                other => other.clone(),
            }
        };
        let w2 = Word {
            parts: w.parts.iter().map(swap).collect(),
            brace: w.brace,
            raw: w.raw.clone(),
        };
        self.resolve(&w2)
    }

    /// `sed -f FILE`: the script is read and checked like one given in
    /// the arguments (G3); the files it writes are returned.
    fn sed_file(&self, file: &str) -> Result<Vec<String>, Deny> {
        let Some(p) = self.abs_path(file) else {
            return Err(format!(
                "sed -f {file} after a cd the guard cannot follow; use an absolute path (G3, G8)"
            ));
        };
        let shown = p.display().to_string();
        let text = if self.was_written(&p) {
            self.known_text(&p, &shown)?
        } else {
            let meta = std::fs::metadata(&p).map_err(|e| {
                format!("the guard reads {shown} before sed runs it and cannot ({e}) (G3)")
            })?;
            if !meta.is_file() || meta.len() > MAX_SCRIPT {
                return Err(format!(
                    "{shown} is not a regular file of at most 1 MiB; the guard cannot read it as a sed script (G3)"
                ));
            }
            String::from_utf8(
                std::fs::read(&p).map_err(|e| format!("cannot read {shown}: {e} (G3)"))?,
            )
            .map_err(|_| format!("{shown} is not UTF-8 text; the guard cannot check it (G3)"))?
        };
        super::progs::sed_script(&text)
    }

    /// `trap CODE SIGNAL...`: the code runs later (G3).
    fn trap(&mut self, argv: &[Word], lits: &[Option<String>]) -> W {
        let mut i = 1;
        match lits.get(i).cloned().flatten().as_deref() {
            Some("--") => i += 1,
            Some("-p" | "-l" | "-P") => return Ok(()),
            _ => {}
        }
        let Some(action) = argv.get(i) else {
            return Ok(());
        };
        let Some(code) = action.literal() else {
            return Err("trap with code that is not a literal word (G3)".into());
        };
        // `trap - SIG` resets; a lone number or signal name only prints.
        if code == "-"
            || code.is_empty()
            || argv.len() == i + 1 && code.bytes().all(|b| b.is_ascii_digit())
        {
            return Ok(());
        }
        let mut exit_only = argv.len() > i + 1;
        for (k, sig) in lits.iter().enumerate().skip(i + 1) {
            let Some(sig) = sig else {
                return Err(format!(
                    "trap on `{}`, a signal bash builds at run time (G3)",
                    argv[k].raw
                ));
            };
            exit_only &= matches!(sig.to_ascii_uppercase().as_str(), "EXIT" | "SIGEXIT" | "0");
        }
        if exit_only {
            self.exit_traps
                .push((code, self.scope.clone(), self.log.len()));
            return Ok(());
        }
        // DEBUG, ERR, RETURN and signals run between any two commands from
        // here on, with whatever values hold then.
        let frame = Frame {
            stdin: Feed::Unknown,
            env: Vec::new(),
        };
        let (lookups, writes) = (self.path_lookups, self.path_writes);
        self.isolated(|w| {
            w.scope.forget();
            w.code(&code, true, &frame, "trap")
        })?;
        // G1, G5 (review G5 PATH): the trap finds its commands on the PATH
        // that holds now, and may change PATH between any two commands.
        self.trap_lookups |= self.path_lookups > lookups;
        if self.path_writes > writes {
            self.path_hidden = true;
        }
        self.scope.forget();
        self.log.push("*".into());
        Ok(())
    }

    fn find(&mut self, argv: &[Word], env: &[EnvSet], f: &Frame) -> W {
        const FLAG_TESTS: &[&str] = &[
            "-print",
            "-print0",
            "-delete",
            "-prune",
            "-quit",
            "-ls",
            "-depth",
            "-follow",
            "-mount",
            "-xdev",
            "-noleaf",
            "-daystart",
            "-true",
            "-false",
            "-empty",
            "-readable",
            "-writable",
            "-executable",
            "-nouser",
            "-nogroup",
            "-ignore_readdir_race",
            "-noignore_readdir_race",
            "-not",
            "-and",
            "-or",
            "-a",
            "-o",
            "-d",
            "-help",
            "--help",
            "-version",
            "--version",
        ];
        self.env_check(env, Target::Other)?;
        let lits = self.lits(argv);
        let mut i = 1;
        // -H -L -P -D debugopts -Olevel before the paths.
        while let Some(Some(a)) = lits.get(i) {
            match a.as_str() {
                "-H" | "-L" | "-P" => i += 1,
                "-D" => i += 2,
                o if o.starts_with("-O") => i += 1,
                _ => break,
            }
        }
        let mut starts = Vec::new();
        while let Some(w) = argv.get(i) {
            let l = lits[i].as_deref();
            if l.is_some_and(|a| a.starts_with('-') || a == "(" || a == "!") {
                break;
            }
            starts.push(w);
            i += 1;
        }
        let mut removal = false;
        // Review G7/R25: `{}` stands for paths in tollgate's dirs there.
        let in_tollgate = starts.iter().any(|w| match self.word_reach(w) {
            Reach::Hit(..) | Reach::TooMany => true,
            Reach::Clear => false,
            Reach::Unknown => self.tollgate_named || paths::spells_tollgate_tail(self.ctx, &w.raw),
        }) || (starts.is_empty()
            && matches!(&self.scope.cwd, Cwd::Known(c) if paths::tollgate_dir(self.ctx, c, false).is_some()));
        // What `-exec` gets for `{}` lies there (a link that does not
        // spell the dir included).
        self.tollgate_named |= in_tollgate;
        while i < argv.len() {
            match lits[i].as_deref() {
                Some("-delete") => removal = true,
                Some("-exec" | "-execdir" | "-ok" | "-okdir") => {
                    let start = i + 1;
                    let end = (start..argv.len())
                        .find(|&j| {
                            lits[j].as_deref() == Some(";")
                                || (lits[j].as_deref() == Some("+")
                                    && lits[j - 1].as_deref() == Some("{}"))
                        })
                        .ok_or("find -exec without its `;` or `{} +` (G2)")?;
                    let inner = &argv[start..end];
                    let Some(first) = inner.first() else {
                        return Err("find -exec without a command (G2)".into());
                    };
                    let name = self.command_word(first)?;
                    if WRITE_CMDS.contains(&basename(&name)) {
                        removal = true;
                    }
                    if in_tollgate && !TOLLGATE_DIR_READERS.contains(&basename(&name)) {
                        return Err(format!(
                            "find -exec {name} on tollgate's dirs: `{{}}` names their files, and {name} is not a known reader (cat, grep, ...) (R25, G7)"
                        ));
                    }
                    self.run(inner, &name, Vec::new(), f, Via::Elsewhere, false)?;
                    i = end;
                }
                Some("-fprint" | "-fprint0" | "-fls" | "-fprintf") => {
                    if let Some(w) = argv.get(i + 1) {
                        self.write_target(w, false, "find -fprint")?;
                    }
                    i += 1;
                }
                Some(_) => {}
                None => {
                    let prev = i.checked_sub(1).and_then(|p| lits[p].as_deref());
                    let is_value =
                        prev.is_some_and(|p| p.starts_with('-') && !FLAG_TESTS.contains(&p));
                    if !is_value {
                        return Err(format!(
                            "find with `{}`, a word bash builds at run time where find reads its expression (G2)",
                            argv[i].raw
                        ));
                    }
                }
            }
            i += 1;
        }
        if removal {
            for s in starts {
                self.write_target(s, true, "find")?;
            }
        }
        Ok(())
    }

    /// The branches whose moves the guard denies in the repo at `dir`
    /// (G7): `main`, `master` and the repo's `policy.anchors`.
    pub(super) fn anchors(&mut self, dir: &Path) -> Vec<String> {
        let root = dir
            .ancestors()
            .find(|a| a.join(".git").exists())
            .map(Path::to_owned)
            .unwrap_or_else(|| dir.to_owned());
        if let Some(a) = self.anchors.get(&root) {
            return a.clone();
        }
        let mut a: Vec<String> = vec!["main".into(), "master".into()];
        a.extend(super::repo_config(&root).policy.anchors);
        a.sort();
        a.dedup();
        self.anchors.insert(root, a.clone());
        a
    }
}

/// `exit` or `return`: what follows `||` after a `cd` that must succeed.
/// True when this process may search `dir` (`cd` into it succeeds).
fn searchable(dir: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    let Ok(c) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c` is a valid NUL-terminated path for the call's duration.
    unsafe { libc::access(c.as_ptr(), libc::X_OK) == 0 }
}

/// The status a pipeline always ends with: `true`, `:`, `false`, and an
/// assignment with no substitution; anything else may fail.
fn status_of(p: &Pipeline) -> Status {
    let [c] = p.cmds.as_slice() else {
        return Status::Unknown;
    };
    let Kind::Simple(sc) = &c.kind else {
        return Status::Unknown;
    };
    if !c.redirs.is_empty() {
        return Status::Unknown;
    }
    let s = match sc.words.first().map(Word::literal) {
        None if sc
            .assigns
            .iter()
            .all(|a| a.value.iter().all(|w| w.scripts().is_empty())) =>
        {
            Status::Succeeded
        }
        Some(Some(w)) if (w == "true" || w == ":") && sc.assigns.is_empty() => Status::Succeeded,
        Some(Some(w)) if w == "false" && sc.assigns.is_empty() => Status::Failed,
        _ => return Status::Unknown,
    };
    match (s, p.negate) {
        (Status::Succeeded, true) => Status::Failed,
        (Status::Failed, true) => Status::Succeeded,
        (s, _) => s,
    }
}

/// The names arithmetic `text` assigns: before an assignment operator
/// (`=`, `+=`, `<<=`, ...; not `==`), or next to `++` or `--`. Names in a
/// subscript count too (`a[i++]`).
fn arith_assigned(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut k = 0;
    while k < b.len() {
        let c = b[k];
        if !(c.is_ascii_alphabetic() || c == b'_')
            || (k > 0 && (b[k - 1].is_ascii_alphanumeric() || b[k - 1] == b'_'))
        {
            k += 1;
            continue;
        }
        let start = k;
        while k < b.len() && (b[k].is_ascii_alphanumeric() || b[k] == b'_') {
            k += 1;
        }
        let id = &text[start..k];
        // Skip a subscript: `a[i] = 1` assigns `a`.
        let mut j = k;
        if j < b.len() && b[j] == b'[' {
            let mut depth = 0;
            while j < b.len() {
                match b[j] {
                    b'[' => depth += 1,
                    b']' => {
                        depth -= 1;
                        if depth == 0 {
                            j += 1;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        while j < b.len() && b[j] == b' ' {
            j += 1;
        }
        let after = &text[j..];
        let mut p = start;
        while p > 0 && b[p - 1] == b' ' {
            p -= 1;
        }
        let before = &text[..p];
        let assigns = after.starts_with("++")
            || after.starts_with("--")
            || before.ends_with("++")
            || before.ends_with("--")
            || [
                "=", "+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|=",
            ]
            .iter()
            .any(|op| after.starts_with(op) && !(*op == "=" && after.starts_with("==")));
        if assigns {
            out.push(id);
        }
    }
    out
}

/// `text` without length expansions (`${#name}`, `${#a[@]}`, `$#`): they
/// are numbers, whatever the value.
fn without_lengths(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(k) = rest.find('$') {
        out.push_str(&rest[..k]);
        let r = &rest[k..];
        if let Some(t) = r.strip_prefix("${#") {
            match t.find('}') {
                Some(end) if !t[..end].contains(['$', '`', ':', '/']) => {
                    out.push('0');
                    rest = &t[end + 1..];
                    continue;
                }
                _ => {}
            }
        } else if let Some(t) = r.strip_prefix("$#") {
            out.push('0');
            rest = t;
            continue;
        }
        out.push('$');
        rest = &r[1..];
    }
    out.push_str(rest);
    out
}

/// The arithmetic of a substring expansion: `:offset[:length]` after the
/// name (not `:-`, `:=`, `:?`, `:+`).
fn substring_part(rest: &str) -> Option<&str> {
    let r = rest.strip_prefix(':')?;
    if r.starts_with(['-', '=', '?', '+']) {
        return None;
    }
    Some(r)
}

fn is_exit(p: &Pipeline) -> bool {
    p.cmds.first().is_some_and(|c| match &c.kind {
        Kind::Simple(s) => s
            .words
            .first()
            .and_then(Word::literal)
            .is_some_and(|w| w == "exit" || w == "return"),
        Kind::Group(s) => s.items.last().is_some_and(|ao| is_exit(&ao.first)),
        _ => false,
    })
}

/// Programs that print, search or describe their words and run none of
/// them: [`Walker::foreign_args`] does not read their words.
const READS_ONLY: &[&str] = &[
    "echo", "man", "info", "tldr", "whatis", "apropos", "help", "type", "which", "whereis", "grep",
    "egrep", "fgrep", "rg", "ag", "ack",
];

fn lit_word(t: &str) -> Word {
    Word {
        parts: vec![Part::Lit(t.to_owned())],
        brace: false,
        raw: t.to_owned(),
    }
}

/// True when ssh's arguments name no remote command and no mode that runs
/// none (`-N`, `-O`, `-G`, `-V`, `-Q`).
fn ssh_without_command(lits: &[String]) -> bool {
    const VAL: &str = "BbcDEeFIiJLlmOoPpQRSWw";
    let mut operands = 0;
    let mut k = 0;
    while k < lits.len() {
        let a = &lits[k];
        if a == "--" {
            operands += lits.len() - k - 1;
            break;
        }
        if let Some(cluster) = a
            .strip_prefix('-')
            .filter(|c| !c.is_empty() && operands == 0)
        {
            for (j, c) in cluster.char_indices() {
                if "NGVQO".contains(c) {
                    return false;
                }
                if VAL.contains(c) {
                    if cluster[j + 1..].is_empty() {
                        k += 1;
                    }
                    break;
                }
            }
        } else {
            operands += 1;
        }
        k += 1;
    }
    operands < 2
}

/// True when `head` starts an ELF or Mach-O binary.
fn is_binary(head: &[u8]) -> bool {
    head.starts_with(b"\x7fELF")
        || head.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || head.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
}

/// The first bytes of a file.
fn read_head(p: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    if p.is_dir() {
        return Ok(Vec::new());
    }
    let mut f = std::fs::File::open(p)?;
    let mut buf = vec![0u8; 256];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(buf)
}

/// The program a `#!` line names (`env` skipped).
fn shebang(head: &[u8]) -> Option<String> {
    let rest = head.strip_prefix(b"#!")?;
    let line = rest.split(|b| *b == b'\n').next().unwrap_or_default();
    let line = String::from_utf8_lossy(line);
    let mut words = line.split_whitespace();
    let first = words.next()?;
    let mut prog = basename(first).to_owned();
    if prog == "env" {
        prog = words
            .find(|w| !w.starts_with('-'))
            .map(|w| basename(w).to_owned())
            .unwrap_or_default();
    }
    Some(prog)
}

/// `osascript` (G3, item 21/20, review G2): only `-e CODE` pairs whose
/// every line displays a notification, dialog or alert, beeps or speaks,
/// and that name nothing that runs or drives another program (`do shell
/// script`, `tell`, `run`, `activate`, `keystroke`, raw `«event»` codes,
/// ...). Script files, stdin, `-l` (JavaScript, with its ObjC bridge) and
/// every other option deny.
fn osascript_ok(lits: &[Option<String>]) -> W {
    const LINES: &[&str] = &[
        "display notification",
        "display dialog",
        "display alert",
        "beep",
        "say",
    ];
    const NAMES: &[&str] = &[
        "shell",
        "script",
        "tell",
        "run",
        "launch",
        "open",
        "activate",
        "keystroke",
        "key ",
        "system",
        "terminal",
        "iterm",
        "load",
        "osax",
        "event",
        "application",
        "app ",
        "\u{ab}",
        "\u{bb}",
        "<<",
        ">>",
        "using terms",
        "do ",
        "path to",
        "posix",
    ];
    let deny = |why: &str| {
        Err(format!(
            "osascript {why}; it runs only -e code that shows a notification, a dialog or an alert, beeps or speaks (G3, item 21/20)"
        ))
    };
    if lits.is_empty() || !lits.len().is_multiple_of(2) {
        return deny("without -e code pairs");
    }
    for pair in lits.chunks(2) {
        let (Some(opt), Some(code)) = (pair[0].as_deref(), pair[1].as_deref()) else {
            return deny("with a word bash builds at run time");
        };
        if opt != "-e" {
            return deny(&format!("with {opt}"));
        }
        let c = code.to_lowercase();
        if let Some(n) = NAMES.iter().find(|n| c.contains(**n)) {
            return deny(&format!("code with `{}`", n.trim()));
        }
        for line in c.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if !LINES.iter().any(|p| line.starts_with(p)) {
                return deny(&format!("code `{line}`"));
            }
        }
    }
    Ok(())
}

/// zsh, fish and csh read some text differently from bash (`=cmd`, fish
/// escapes in single quotes); code for them must avoid those forms.
fn foreign_shell_ok(sh: &str, code: &str) -> W {
    let bad = code.contains('\\')
        || code
            .split(|c: char| c.is_whitespace() || matches!(c, ';' | '&' | '|'))
            .any(|w| w.starts_with('='));
    if bad {
        return Err(format!(
            "{sh} code with `\\` or a word starting with `=`, which {sh} reads differently from bash; the guard cannot check it (G3)"
        ));
    }
    Ok(())
}

/// Review G7/R25: programs that only read the files they are given (or
/// whose writes [`write_targets`] parses: sed's `-i` and `w`, `sort -o`
/// and `-T`, `uniq IN OUT`), so they may name paths in tollgate's dirs
/// and run there. Any other program may write a path it is given (`curl
/// -o`, `xxd -r IN OUT`, `file -C`, `tree -o`, `less -o`), so it may
/// not.
const TOLLGATE_DIR_READERS: &[&str] = &[
    "cat",
    "tac",
    "more",
    "head",
    "tail",
    "grep",
    "egrep",
    "fgrep",
    "rg",
    "ag",
    "ack",
    "jq",
    "ls",
    "stat",
    "wc",
    "du",
    "df",
    "diff",
    "cmp",
    "md5sum",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "b2sum",
    "b3sum",
    "cksum",
    "readlink",
    "realpath",
    "basename",
    "dirname",
    "test",
    "[",
    "echo",
    "printf",
    "pwd",
    "true",
    "false",
    ":",
    "sed",
    "od",
    "hexdump",
    "strings",
    "nl",
    "cut",
    "sleep",
    "date",
    "sort",
    "uniq",
    "tr",
    "column",
    "fold",
    "fmt",
    "expand",
    "unexpand",
    "paste",
    "join",
    "comm",
    "rev",
    "seq",
    // Shell builtins that open no file.
    "break",
    "continue",
    "return",
    "exit",
    "shift",
    "set",
    "shopt",
    "wait",
    "times",
];

/// Review G7/R25: the indices in `argv` of the sources of `cp` or
/// `install`, which they only read; none when they may link them to the
/// target (`-l`, `-s`, `--link`, `--symbolic-link`, a word bash builds),
/// since a later write of the link writes the source. A value option
/// the parse does not know leaves its value a source only when it is not
/// the last word; a misparse checks more words, never fewer.
fn copy_sources(base: &str, argv: &[Word], lits: &[Option<String>]) -> Vec<usize> {
    if !matches!(base, "cp" | "install") {
        return Vec::new();
    }
    let la = &lits[1..];
    let mut dashdash = false;
    for a in la {
        let Some(a) = a.as_deref() else {
            return Vec::new();
        };
        if dashdash {
            continue;
        }
        if a == "--" {
            dashdash = true;
        } else if let Some(long) = a.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or_default();
            if !name.is_empty() && ("link".starts_with(name) || "symbolic-link".starts_with(name)) {
                return Vec::new();
            }
        } else if a.len() > 1 && a.starts_with('-') && a[1..].contains(['l', 's']) {
            return Vec::new();
        }
    }
    let (pos, _) = positionals(
        &argv[1..],
        la,
        "tSmogeT",
        &[
            "--target-directory",
            "--suffix",
            "--mode",
            "--owner",
            "--group",
        ],
    );
    let to_dir = la.iter().flatten().any(|a| {
        a.starts_with("--target-directory")
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('t'))
    });
    let n = if to_dir {
        pos.len()
    } else {
        pos.len().saturating_sub(1)
    };
    pos[..n]
        .iter()
        .filter_map(|w| argv.iter().position(|a| std::ptr::eq(a, *w)))
        .collect()
}

/// Commands that write or remove files named in their arguments.
const WRITE_CMDS: &[&str] = &[
    "rm", "rmdir", "unlink", "shred", "mv", "cp", "install", "rsync", "ln", "tee", "touch",
    "mkdir", "truncate", "setfattr", "chmod", "chown", "chgrp", "sed", "perl", "dd",
];

/// The positional words of `args` (options and the values of `val_short`
/// and `val_long` skipped; a non-literal word is positional).
fn positionals<'w>(
    args: &'w [Word],
    lits: &[Option<String>],
    val_short: &str,
    val_long: &[&str],
) -> (Vec<&'w Word>, Vec<&'w Word>) {
    let mut pos = Vec::new();
    let mut values = Vec::new();
    let mut k = 0;
    let mut dashdash = false;
    while k < args.len() {
        let w = &args[k];
        match lits[k].as_deref() {
            Some("--") if !dashdash => dashdash = true,
            Some(a) if !dashdash && a.starts_with("--") => {
                if val_long.contains(&a) {
                    k += 1;
                    if let Some(v) = args.get(k) {
                        values.push(v);
                    }
                }
            }
            Some(a) if !dashdash && a.starts_with('-') && a.len() > 1 => {
                let cluster = &a[1..];
                for (j, c) in cluster.char_indices() {
                    if val_short.contains(c) {
                        if cluster[j + 1..].is_empty() {
                            k += 1;
                            if let Some(v) = args.get(k) {
                                values.push(v);
                            }
                        }
                        break;
                    }
                }
            }
            _ => pos.push(w),
        }
        k += 1;
    }
    (pos, values)
}

/// The paths command `base` writes or removes (`true`: removal).
fn write_targets(base: &str, argv: &[Word], lits: &[Option<String>]) -> Vec<(Word, bool)> {
    let args = &argv[1..];
    let la = &lits[1..];
    let target_dir = || {
        let (_, v) = positionals(args, la, "tST", &["--target-directory", "--suffix"]);
        let mut out: Vec<&Word> = Vec::new();
        for (k, a) in la.iter().enumerate() {
            if matches!(a.as_deref(), Some("-t" | "--target-directory")) {
                out.extend(args.get(k + 1));
            }
        }
        let _ = v;
        out
    };
    let all = |pos: Vec<&Word>, removal: bool| {
        pos.into_iter()
            .map(|w| (w.clone(), removal))
            .collect::<Vec<_>>()
    };
    match base {
        "rm" | "rmdir" | "unlink" | "shred" => all(positionals(args, la, "nu", &[]).0, true),
        "mv" => {
            let mut v = all(
                positionals(args, la, "tS", &["--target-directory", "--suffix"]).0,
                true,
            );
            v.extend(target_dir().into_iter().map(|w| (w.clone(), true)));
            v
        }
        "cp" | "install" | "rsync" => {
            let (pos, _) = positionals(
                args,
                la,
                "tSmogeT",
                &[
                    "--target-directory",
                    "--suffix",
                    "--mode",
                    "--owner",
                    "--group",
                    "--rsh",
                ],
            );
            let mut v: Vec<(Word, bool)> = pos
                .last()
                .map(|w| ((*w).clone(), false))
                .into_iter()
                .collect();
            v.extend(target_dir().into_iter().map(|w| (w.clone(), false)));
            v
        }
        "ln" => {
            let mut v = all(
                positionals(args, la, "tS", &["--target-directory", "--suffix"]).0,
                false,
            );
            v.extend(target_dir().into_iter().map(|w| (w.clone(), false)));
            v
        }
        "tee" | "touch" | "mkdir" => all(
            positionals(args, la, "mdrt", &["--mode", "--date", "--reference"]).0,
            false,
        ),
        "truncate" => all(
            positionals(args, la, "sor", &["--size", "--reference"]).0,
            false,
        ),
        "setfattr" => all(
            positionals(
                args,
                la,
                "nvx",
                &["--name", "--value", "--remove", "--restore"],
            )
            .0,
            false,
        ),
        "chmod" | "chown" | "chgrp" => {
            let reference = la.iter().flatten().any(|a| a.starts_with("--reference"));
            let pos = positionals(args, la, "", &[]).0;
            all(
                pos.into_iter().skip(usize::from(!reference)).collect(),
                false,
            )
        }
        "sed" => {
            let in_place = la.iter().flatten().any(|a| {
                a == "--in-place"
                    || a.starts_with("--in-place=")
                    || (a.starts_with('-') && !a.starts_with("--") && a.contains('i'))
            });
            if !in_place {
                return Vec::new();
            }
            let script_given = la.iter().flatten().any(|a| {
                a == "-e"
                    || a == "-f"
                    || a.starts_with("--expression")
                    || a.starts_with("--file")
                    || (a.starts_with('-')
                        && !a.starts_with("--")
                        && (a.ends_with('e') || a.ends_with('f')))
            });
            let pos = positionals(
                args,
                la,
                "efl",
                &["--expression", "--file", "--line-length"],
            )
            .0;
            all(
                pos.into_iter().skip(usize::from(!script_given)).collect(),
                false,
            )
        }
        // Review G7/R25: `-o FILE` (also glued, `--output[=]` and its
        // prefixes) and the temporary dir `-T DIR` (`--temporary-directory`)
        // are written; `-k`, `-t`, `-S` take a value.
        "sort" => {
            let mut out = Vec::new();
            let mut k = 0;
            while k < args.len() {
                match la[k].as_deref() {
                    Some("--") => break,
                    Some(a) if a.starts_with("--") => {
                        let (name, value) = match a[2..].split_once('=') {
                            Some((n, v)) => (n, Some(v)),
                            None => (&a[2..], None),
                        };
                        let writes = !name.is_empty()
                            && ("output".starts_with(name)
                                || "temporary-directory".starts_with(name));
                        let takes = writes
                            || [
                                "key",
                                "field-separator",
                                "buffer-size",
                                "files0-from",
                                "random-source",
                                "compress-program",
                                "batch-size",
                                "parallel",
                                "sort",
                            ]
                            .iter()
                            .any(|l| !name.is_empty() && l.starts_with(name));
                        match value {
                            Some(v) if writes => out.push((lit_word(v), false)),
                            None if takes => {
                                k += 1;
                                if writes && let Some(w) = args.get(k) {
                                    out.push((w.clone(), false));
                                }
                            }
                            _ => {}
                        }
                    }
                    Some(a) if a.len() > 1 && a.starts_with('-') => {
                        for (j, c) in a.char_indices().skip(1) {
                            if "ktoST".contains(c) {
                                let rest = &a[j + 1..];
                                let value = if rest.is_empty() {
                                    k += 1;
                                    args.get(k).cloned()
                                } else {
                                    Some(lit_word(rest))
                                };
                                if matches!(c, 'o' | 'T')
                                    && let Some(v) = value
                                {
                                    out.push((v, false));
                                }
                                break;
                            }
                        }
                    }
                    // A word bash builds may be an option (`-o/x`, or `-o`
                    // with the next word as its value), unless it starts
                    // with text that is not `-`.
                    None => {
                        let (prefix, _) = args[k].literal_prefix();
                        if prefix.starts_with('-') {
                            out.push((args[k].clone(), false));
                        }
                        if (prefix.is_empty() || prefix.starts_with('-'))
                            && let Some(w) = args.get(k + 1)
                        {
                            out.push((w.clone(), false));
                        }
                    }
                    Some(_) => {}
                }
                k += 1;
            }
            out
        }
        "uniq" => {
            let (pos, _) = positionals(
                args,
                la,
                "fsw",
                &["--skip-fields", "--skip-chars", "--check-chars"],
            );
            // An unquoted word bash builds may split into IN and OUT.
            let split =
                matches!(pos.as_slice(), [w] if w.literal().is_none() && !w.raw.starts_with('"'));
            if split {
                return all(pos, false);
            }
            pos.get(1)
                .map(|w| ((*w).clone(), false))
                .into_iter()
                .collect()
        }
        "perl" => {
            let in_place = la
                .iter()
                .flatten()
                .any(|a| a.starts_with('-') && !a.starts_with("--") && a.contains('i'));
            if !in_place {
                return Vec::new();
            }
            let code_given = la.iter().flatten().any(|a| {
                a.starts_with('-') && !a.starts_with("--") && (a.contains('e') || a.contains('E'))
            });
            let pos = positionals(args, la, "eEIMmx", &[]).0;
            all(
                pos.into_iter().skip(usize::from(!code_given)).collect(),
                false,
            )
        }
        "dd" => args
            .iter()
            .filter_map(|w| shell::split_assign(w).filter(|(n, _)| n == "of"))
            .map(|(_, v)| (v, false))
            .collect(),
        _ => Vec::new(),
    }
}

/// `gawk -i inplace` (also `-iinplace`, `--include[=]inplace`, the
/// `.awk` file name) writes every file operand (R25, R26, G7). The
/// program is the first operand unless `-f`, `-e` or their long forms
/// give it; `name=value` operands are assignments.
fn awk_in_place(argv: &[Word], lits: &[Option<String>]) -> Vec<(Word, bool)> {
    let args = &argv[1..];
    let la = &lits[1..];
    let is_inplace = |v: &str| v == "inplace" || v == "inplace.awk";
    let mut in_place = false;
    let mut prog_given = false;
    for (k, a) in la.iter().enumerate() {
        let Some(a) = a.as_deref() else { continue };
        let next = la.get(k + 1).cloned().flatten().unwrap_or_default();
        in_place |= ((a == "-i" || a == "--include") && is_inplace(&next))
            || a.strip_prefix("-i").is_some_and(is_inplace)
            || a.strip_prefix("--include=").is_some_and(is_inplace);
        prog_given |= matches!(a, "-f" | "-e" | "--file" | "--source")
            || a.starts_with("--file=")
            || a.starts_with("--source=")
            || (a.starts_with("-f") || a.starts_with("-e")) && a.len() > 2 && !a.starts_with("--");
    }
    if !in_place {
        return Vec::new();
    }
    let (pos, _) = positionals(
        args,
        la,
        "fvFilEe",
        &[
            "--file",
            "--assign",
            "--field-separator",
            "--include",
            "--load",
            "--source",
            "--exec",
        ],
    );
    pos.into_iter()
        .skip(usize::from(!prog_given))
        .filter(|w| {
            !w.literal().is_some_and(|l| {
                l.split_once('=').is_some_and(|(n, _)| {
                    !n.is_empty() && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                })
            })
        })
        .map(|w| (w.clone(), false))
        .collect()
}

/// A program file an interpreter may run.
enum ProgArg {
    /// Part of an option word (`-fprog.awk`, `--file=prog.awk`).
    Text(String),
    /// The whole word at this index of argv.
    Word(usize),
}

/// Where an interpreter takes its program from.
enum Program {
    Inline(String),
    /// Program files the interpreter may run (`None`: a word bash builds
    /// at run time); a module (`python -m`) names none.
    File(Vec<ProgArg>),
    Stdin,
    None,
}

/// Parses an interpreter's options (G3).
fn interp_program(lang: Lang, lits: &[Option<String>], argv: &[Word]) -> Result<Program, Deny> {
    let base = lits[0].as_deref().map_or("", basename);
    let nonlit = |k: usize| {
        format!(
            "{base} with `{}`, inline code bash builds at run time; the guard scans only literal code (G3)",
            argv[k].raw
        )
    };
    // (letters whose value is code, letters with a value, long code
    // options, long options with a value)
    let (code_short, val_short, code_long, val_long): (&str, &str, &[&str], &[&str]) = match lang {
        Lang::Python => ("c", "mWXQ", &[], &[]),
        Lang::Perl => ("eE", "IMmxilCd0D", &[], &[]),
        Lang::Ruby => ("e", "rICEFxT", &[], &[]),
        Lang::Node => (
            "ep",
            "r",
            &["--eval", "--print"],
            &["--require", "--import", "--loader", "--input-type"],
        ),
        Lang::Bun => (
            "ep",
            "r",
            &["--eval", "--print"],
            &["--preload", "--require", "--cwd", "--config", "--env-file"],
        ),
        Lang::Php => ("rBRE", "fcdz", &[], &[]),
        Lang::Lua => ("e", "l", &[], &[]),
        Lang::Awk => (
            "e",
            "FvfEil",
            &["--source"],
            &[
                "--file",
                "--include",
                "--load",
                "--assign",
                "--field-separator",
            ],
        ),
        Lang::Deno => {
            // `deno eval [options] CODE`; other subcommands run files.
            let Some(k) = lits.iter().position(|l| l.as_deref() == Some("eval")) else {
                // `deno run [options] FILE`: any operand may be the file.
                return Ok(Program::File(
                    (1..lits.len())
                        .filter(|&j| !lits[j].as_deref().is_some_and(|a| a.starts_with('-')))
                        .map(ProgArg::Word)
                        .collect(),
                ));
            };
            let Some(j) = (k + 1..lits.len())
                .find(|&j| !lits[j].as_deref().is_some_and(|a| a.starts_with('-')))
            else {
                return Ok(Program::None);
            };
            return lits[j]
                .clone()
                .map(Program::Inline)
                .ok_or_else(|| nonlit(j));
        }
    };
    let mut code = String::new();
    let mut from_file = false;
    let mut files: Vec<ProgArg> = Vec::new();
    let mut k = 1;
    while k < lits.len() {
        let Some(a) = lits[k].as_deref() else {
            if code.is_empty() && !from_file && lang != Lang::Awk {
                // A script path or argument built at run time.
                return Ok(Program::File(vec![ProgArg::Word(k)]));
            }
            return Err(nonlit(k));
        };
        if a == "--" {
            k += 1;
            break;
        }
        if a == "-" {
            return Ok(if code.is_empty() {
                Program::Stdin
            } else {
                Program::Inline(code)
            });
        }
        if let Some(long) = a.strip_prefix("--").filter(|l| !l.is_empty()) {
            let (n, glued) = match long.split_once('=') {
                Some((n, v)) => (format!("--{n}"), Some(v.to_owned())),
                None => (a.to_owned(), None),
            };
            if code_long.contains(&n.as_str()) {
                let v = match glued {
                    Some(v) => v,
                    None => {
                        k += 1;
                        lits.get(k)
                            .cloned()
                            .flatten()
                            .ok_or_else(|| nonlit(k.min(lits.len() - 1)))?
                    }
                };
                code.push_str(&v);
                code.push('\n');
            } else if val_long.contains(&n.as_str()) {
                if matches!(n.as_str(), "--file") {
                    from_file = true;
                    files.push(match glued.clone() {
                        Some(v) => ProgArg::Text(v),
                        None => ProgArg::Word(k + 1),
                    });
                }
                if glued.is_none() {
                    k += 1;
                }
            }
            k += 1;
            continue;
        }
        if let Some(cluster) = a.strip_prefix('-').filter(|c| !c.is_empty()) {
            for (j, c) in cluster.char_indices() {
                let rest = &cluster[j + c.len_utf8()..];
                if code_short.contains(c) {
                    let v = if rest.is_empty() {
                        k += 1;
                        lits.get(k)
                            .cloned()
                            .flatten()
                            .ok_or_else(|| nonlit(k.min(lits.len() - 1)))?
                    } else {
                        rest.to_owned()
                    };
                    code.push_str(&v);
                    code.push('\n');
                    break;
                }
                if val_short.contains(c) {
                    if lang == Lang::Python && c == 'm' {
                        return Ok(Program::File(Vec::new()));
                    }
                    if lang == Lang::Awk && matches!(c, 'f' | 'E') || lang == Lang::Php && c == 'f'
                    {
                        from_file = true;
                        files.push(if rest.is_empty() {
                            ProgArg::Word(k + 1)
                        } else {
                            ProgArg::Text(rest.to_owned())
                        });
                    }
                    if rest.is_empty() && !(lang == Lang::Perl) {
                        k += 1;
                    }
                    break;
                }
            }
            k += 1;
            continue;
        }
        break;
    }
    if !code.is_empty() {
        return Ok(Program::Inline(code));
    }
    if from_file {
        return Ok(Program::File(files));
    }
    if lang == Lang::Awk {
        // The first operand is the program.
        return match lits.get(k) {
            Some(Some(p)) => Ok(Program::Inline(p.clone())),
            Some(None) => Err(nonlit(k)),
            None => Ok(Program::None),
        };
    }
    if k < lits.len() {
        return Ok(Program::File(vec![ProgArg::Word(k)]));
    }
    if matches!(lang, Lang::Bun | Lang::Deno) {
        return Ok(Program::None);
    }
    Ok(Program::Stdin)
}
