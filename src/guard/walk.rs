//! The open-grammar walker (R25, R26, R28).
//!
//! The guard stops a careless agent, not a hostile one. The walker reads
//! a Bash command as bash reads it ([`super::shell`]), finds the commands
//! that run, and applies the rules to literal words at command position:
//! the `git` rules ([`super::git`]), the injection rules (`env-i`,
//! `git-config-env`), the person-only `tollgate` subcommands, and the
//! path rules for the files that ordinary tools write
//! ([`rules::write_ruling`]). Every other word is data.
//!
//! It follows what a careless command uses: lists, pipelines, subshells,
//! groups, compound commands, substitutions, `sh -c` and `eval` with
//! literal text, a heredoc or literal pipe into a shell, plain wrappers
//! ([`cmds::wrapper`]), script runners ([`super::runners`]), script files
//! that a shell runs (depth 3, 16 files, 1 MiB), a script that the same
//! command writes, literal variable assignments and a literal `cd`.
//!
//! One ask rule, `unclassified`, covers what the walker cannot read when
//! that fragment names git, tollgate or a protected path; the case number
//! is in the reason:
//!
//! 1. the command does not parse;
//! 2. shell code made at run time;
//! 3. a command name made at run time;
//! 4. a script file that does not parse or is over the budget;
//! 5. an unknown program whose arguments are a refused command;
//! 6. a write target with a part made at run time.

use std::collections::HashMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use super::cmds::{self, Arg, DYNAMIC, Wrapper, operands_at};
use super::git;
use super::paths;
use super::rules::{self, Assessment, Context, Ruling};
use super::runners::{self, Runner};
use super::shell::{self, AndOr, Command, Kind, Op, Part, Pipeline, Redir, Script, Simple, Word};

/// Script files inside script files that the walker reads.
const MAX_DEPTH: usize = 3;
/// Script files the walker reads for one command.
const MAX_FILES: usize = 16;
/// Bytes of script files the walker reads for one command.
const MAX_BYTES: usize = 1 << 20;
/// Levels of code inside code (`sh -c "sh -c ..."`, `x='eval $x'`).
const MAX_NEST: usize = 8;

/// The verdict on `command` and whether it needs the R28 rewrite.
pub fn assess(ctx: &Context, command: &str) -> Assessment {
    let script = match shell::parse(command) {
        Ok(s) => s,
        Err(e) => {
            let ruling = if has_needle(command) {
                Ruling::ask(
                    "unclassified",
                    format!(
                        "the command does not parse as bash ({e}) and names git, tollgate or .claude; a person decides (R26, case 1)"
                    ),
                )
            } else {
                Ruling::Allow
            };
            return Assessment {
                ruling,
                long_timeout: false,
            };
        }
    };
    let mut w = Walker::new(ctx, command);
    let mut st = State {
        cwd: Some(ctx.cwd.clone()),
        lost: false,
        taint: None,
        depth: 0,
        nest: 0,
    };
    w.script(&script, &mut st);
    Assessment {
        ruling: w.ruling,
        long_timeout: w.long_timeout,
    }
}

/// True when `text` names git (as a word: not `digit`, `github` or
/// `.gitignore`), tollgate, `.claude` or `.githooks`.
pub fn has_needle(text: &str) -> bool {
    let t = text.to_ascii_lowercase();
    if t.contains("tollgate") || t.contains(".claude") || t.contains(".githooks") {
        return true;
    }
    let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    let b = t.as_bytes();
    t.match_indices("git").any(|(k, _)| {
        let before = k > 0 && word(b[k - 1]);
        let after = b.get(k + 3).is_some_and(|c| word(*c));
        !before && !after
    })
}

/// A file the same command wrote before it runs it.
#[derive(Clone)]
enum Written {
    /// Literal text (a quoted heredoc, a literal `echo` or `printf`).
    Text(String),
    /// Text made at run time: the words of the command that wrote it.
    Runtime(String),
}

impl Written {
    fn text(&self) -> &str {
        match self {
            Self::Text(t) | Self::Runtime(t) => t,
        }
    }
}

/// What the walker knows at one point of the command.
#[derive(Clone)]
struct State {
    /// The current dir; `None` after a `cd` the walker cannot follow.
    cwd: Option<PathBuf>,
    /// The hook injection is lost (`env -i`, `exec -c`, `sudo`).
    lost: bool,
    /// A variable that changes what git or tollgate run is set.
    taint: Option<String>,
    /// Script files above this code.
    depth: usize,
    /// Code strings above this code.
    nest: usize,
}

/// The stdin and the source text of the simple command that runs.
#[derive(Clone, Copy)]
struct Io<'a> {
    redirs: &'a [Redir],
    /// The command before it in the pipeline.
    feeder: Option<&'a Command>,
    /// The simple command as written.
    raw: &'a str,
}

impl<'a> Io<'a> {
    /// For a command that a wrapper starts with its own stdin (`xargs`,
    /// `find -exec`).
    fn detached(self) -> Self {
        Io {
            redirs: &[],
            feeder: None,
            raw: self.raw,
        }
    }
}

struct Walker<'a> {
    ctx: &'a Context,
    /// The whole command.
    text: &'a str,
    ruling: Ruling,
    long_timeout: bool,
    /// Literal assignments; `None` for a value made at run time.
    vars: HashMap<String, Option<String>>,
    written: HashMap<PathBuf, Written>,
    files: usize,
    bytes: usize,
    /// The last two components of each tollgate dir, lowercase.
    tails: Vec<String>,
}

fn config_var(name: &str) -> bool {
    matches!(name, "GIT_CONFIG_COUNT" | "GIT_CONFIG_PARAMETERS")
        || name.starts_with("GIT_CONFIG_KEY_")
        || name.starts_with("GIT_CONFIG_VALUE_")
}

fn taint_var(name: &str) -> bool {
    matches!(
        name,
        "GIT_SSH" | "GIT_SSH_COMMAND" | "GIT_SSH_VARIANT" | "GIT_PROXY_COMMAND" | "GIT_EXEC_PATH"
    ) || name.starts_with("TOLLGATE_")
}

fn config_env_deny(name: &str, how: &str) -> Ruling {
    Ruling::deny(
        "git-config-env",
        format!(
            "{how} changes `{name}`, which carries the hook injection (core.hooksPath) to git; leave the GIT_CONFIG_* variables as the session has them (R25)"
        ),
    )
}

fn join(args: &[Arg]) -> String {
    args.iter()
        .map(|a| a.s.as_str())
        .collect::<Vec<_>>()
        .join(" ")
}

fn unescape(t: &str) -> String {
    t.replace("\\n", "\n").replace("\\t", "\t")
}

/// `pat` (with `*`, `?` and `[...]`) against `name`; a bracket expression
/// matches any one character.
fn wild(pat: &[u8], name: &[u8]) -> bool {
    match pat.first() {
        None => name.is_empty(),
        Some(b'*') => (0..=name.len()).any(|k| wild(&pat[1..], &name[k..])),
        Some(b'?') => !name.is_empty() && wild(&pat[1..], &name[1..]),
        Some(b'[') => {
            let end = pat.iter().position(|c| *c == b']').map_or(1, |k| k + 1);
            !name.is_empty() && wild(&pat[end..], &name[1..])
        }
        Some(c) => {
            name.first().is_some_and(|n| n.eq_ignore_ascii_case(c)) && wild(&pat[1..], &name[1..])
        }
    }
}

impl<'a> Walker<'a> {
    fn new(ctx: &'a Context, text: &'a str) -> Self {
        let tails = ctx
            .protected
            .iter()
            .filter_map(|d| {
                let c: Vec<_> = d.components().rev().take(2).collect();
                let [last, parent] = c.as_slice() else {
                    return None;
                };
                Some(
                    format!(
                        "{}/{}",
                        parent.as_os_str().to_string_lossy(),
                        last.as_os_str().to_string_lossy()
                    )
                    .to_lowercase(),
                )
            })
            .collect();
        Self {
            ctx,
            text,
            ruling: Ruling::Allow,
            long_timeout: false,
            vars: HashMap::new(),
            written: HashMap::new(),
            files: 0,
            bytes: 0,
            tails,
        }
    }

    fn add(&mut self, r: Ruling) {
        self.ruling = std::mem::replace(&mut self.ruling, Ruling::Allow).max(r);
    }

    /// The `unclassified` ask (R26) for `what`.
    fn unclassified(&mut self, case: u8, what: &str) {
        self.add(Ruling::ask(
            "unclassified",
            format!(
                "{what}: the guard cannot read it, and it names git, tollgate or a protected path; a person decides (R26, case {case})"
            ),
        ));
    }

    /// True when `text` spells a protected path: Claude Code settings,
    /// the git internals, a repo hooks dir, a tollgate dir.
    fn path_marker(&self, text: &str) -> bool {
        let t = text.to_lowercase();
        [
            ".claude/settings",
            ".git/hooks",
            ".git/config",
            ".git/refs",
            ".git/packed-refs",
            ".git/head",
            ".githooks/",
        ]
        .iter()
        .any(|m| t.contains(m))
            || self.tails.iter().any(|m| t.contains(m.as_str()))
    }

    /// True when `text` carries a bypass marker: a protected path, the
    /// hook-skip option, a `core.hooksPath` key, a `GIT_CONFIG_` name, a
    /// person-only subcommand.
    fn has_marker(&self, text: &str) -> bool {
        let t = text.to_lowercase();
        self.path_marker(&t)
            || t.contains("--no-verify")
            || t.contains("core.hookspath")
            || t.contains("git_config_")
            || (t.contains("tollgate")
                && [
                    " install",
                    " uninstall",
                    "remotes forget",
                    "baseline record",
                ]
                .iter()
                .any(|m| t.contains(m)))
    }

    /// Case 2: shell code made at run time; `fragment` is what is known
    /// of it.
    fn runtime(&mut self, fragment: &str) {
        if has_needle(fragment) || self.has_marker(fragment) {
            self.unclassified(2, "shell code made at run time");
        }
    }

    // ---- words ----

    fn lookup(&self, name: &str) -> Option<String> {
        match self.vars.get(name) {
            Some(v) => v.clone(),
            None => self.ctx.var(name).map(str::to_owned),
        }
    }

    fn param(&self, name: &str, subs: &[Script]) -> Option<String> {
        if !subs.is_empty() {
            return None;
        }
        self.lookup(shell::simple_param(name)?)
    }

    /// The word bash passes; a part that is only known at run time
    /// becomes [`DYNAMIC`].
    fn arg(&self, w: &Word) -> Arg {
        let mut s = String::new();
        let mut dynamic = w.brace;
        let mut put = |s: &mut String, v: Option<String>| match v {
            Some(v) => s.push_str(&v),
            None => {
                s.push(DYNAMIC);
                dynamic = true;
            }
        };
        for (k, p) in w.parts.iter().enumerate() {
            match p {
                Part::Lit(t) | Part::Single(t) => s.push_str(t),
                Part::Double(inner) => {
                    for q in inner {
                        match q {
                            Part::Lit(t) => s.push_str(t),
                            Part::Param(name, subs) => put(&mut s, self.param(name, subs)),
                            Part::CmdSub(sc) => put(&mut s, sc.cat_heredoc()),
                            _ => put(&mut s, None),
                        }
                    }
                }
                Part::Param(name, subs) => put(&mut s, self.param(name, subs)),
                Part::Tilde(user) if k == 0 && user.is_empty() => {
                    s.push_str(&self.ctx.home.to_string_lossy());
                }
                Part::Glob(c) => s.push(*c),
                Part::AnsiC(t) if !t.contains('\\') => s.push_str(t),
                _ => put(&mut s, None),
            }
        }
        Arg { s, dynamic }
    }

    /// The words of a simple command. A word that is one unquoted
    /// parameter with a known value is split on blanks, as bash does
    /// (`cmd="git status"; $cmd`).
    fn words(&self, words: &[Word]) -> Vec<Arg> {
        let mut out = Vec::with_capacity(words.len());
        for w in words {
            if let [Part::Param(name, subs)] = w.parts.as_slice()
                && let Some(v) = self.param(name, subs)
            {
                out.extend(v.split_whitespace().map(Arg::fixed));
            } else {
                out.push(self.arg(w));
            }
        }
        out
    }

    // ---- structure ----

    fn script(&mut self, s: &Script, st: &mut State) {
        for ao in &s.items {
            if ao.background {
                self.and_or(ao, &mut st.clone());
            } else {
                self.and_or(ao, st);
            }
        }
    }

    /// `s` in a copy of the state (a substitution, a subshell).
    fn sub(&mut self, s: &Script, st: &State) {
        self.script(s, &mut st.clone());
    }

    fn subs(&mut self, scripts: Vec<&Script>, st: &State) {
        for s in scripts {
            self.sub(s, st);
        }
    }

    fn and_or(&mut self, ao: &AndOr, st: &mut State) {
        self.pipeline(&ao.first, st);
        for (_, p) in &ao.rest {
            self.pipeline(p, st);
        }
    }

    fn pipeline(&mut self, p: &Pipeline, st: &mut State) {
        if let [c] = p.cmds.as_slice() {
            self.command(c, st, None);
            return;
        }
        let mut prev = None;
        for c in &p.cmds {
            self.command(c, &mut st.clone(), prev);
            prev = Some(c);
        }
    }

    /// A body that may or may not run: what it changes is not certain
    /// after it.
    fn branch(&mut self, body: &Script, st: &mut State) {
        let mut sub = st.clone();
        self.script(body, &mut sub);
        if sub.cwd != st.cwd {
            st.cwd = None;
        }
        st.lost |= sub.lost;
        if sub.taint.is_some() {
            st.taint = sub.taint;
        }
    }

    fn command(&mut self, c: &Command, st: &mut State, feeder: Option<&Command>) {
        for r in &c.redirs {
            self.subs(r.target.scripts(), st);
            if let Some(doc) = &r.doc {
                let doc = doc.borrow();
                if !doc.quoted {
                    self.subs(shell::part_scripts(&doc.parts), st);
                }
            }
            if r.writes_file() {
                let t = self.arg(&r.target);
                self.write(&t, false, "a redirection", st.cwd.as_deref());
            }
        }
        match &c.kind {
            Kind::Simple(s) => self.simple(s, c, st, feeder),
            Kind::Subshell(s) => self.sub(s, st),
            Kind::Group(s) => self.script(s, st),
            Kind::If { arms, other } => {
                for (cond, body) in arms {
                    self.script(cond, st);
                    self.branch(body, st);
                }
                if let Some(o) = other {
                    self.branch(o, st);
                }
            }
            Kind::Loop { cond, body } => {
                self.script(cond, st);
                self.branch(body, st);
            }
            Kind::For { var, items, body } => {
                let mut value = None;
                if let Some(items) = items {
                    for w in items {
                        self.subs(w.scripts(), st);
                    }
                    if let [one] = items.as_slice() {
                        value = self.arg(one).lit().map(str::to_owned);
                    }
                }
                if let Some(name) = var.literal() {
                    self.vars.insert(name, value);
                }
                self.branch(body, st);
            }
            Kind::ArithFor { header, body } => {
                self.subs(shell::part_scripts(std::slice::from_ref(header)), st);
                self.branch(body, st);
            }
            Kind::Case { subject, arms } => {
                self.subs(subject.scripts(), st);
                for (pats, body) in arms {
                    for p in pats {
                        self.subs(p.scripts(), st);
                    }
                    self.branch(body, st);
                }
            }
            Kind::Func { body, .. } => self.command(body, &mut st.clone(), None),
            Kind::Cond(words) => {
                for w in words {
                    self.subs(w.scripts(), st);
                }
            }
            Kind::Arith(p) => self.subs(shell::part_scripts(std::slice::from_ref(p)), st),
        }
    }

    fn simple(&mut self, s: &Simple, c: &Command, st: &mut State, feeder: Option<&Command>) {
        for w in s
            .words
            .iter()
            .chain(s.assigns.iter().flat_map(|a| &a.value))
        {
            self.subs(w.scripts(), st);
        }
        let args = self.words(&s.words);
        let saved = st.taint.clone();
        let mut prefix_taint = false;
        for a in &s.assigns {
            let plain = !a.array && a.raw.starts_with(&format!("{}=", a.name));
            let value = match a.value.as_slice() {
                [] if plain => Some(String::new()),
                [w] if plain => self.arg(w).lit().map(str::to_owned),
                _ => None,
            };
            if config_var(&a.name) {
                self.add(config_env_deny(&a.name, "an assignment"));
            } else if taint_var(&a.name) {
                if !self.cap_ok(&a.name, value.as_deref()) {
                    st.taint = Some(a.name.clone());
                    prefix_taint |= !args.is_empty();
                }
            } else if args.is_empty() {
                self.vars.insert(a.name.clone(), value);
            }
        }
        let raw = s
            .words
            .iter()
            .map(|w| w.raw.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        self.record(&args, c, st, &raw);
        let io = Io {
            redirs: &c.redirs,
            feeder,
            raw: &raw,
        };
        self.run(&args, st, io);
        if prefix_taint {
            st.taint = saved;
        }
    }

    /// A client may only lower the inline cap, with a literal number.
    fn cap_ok(&self, name: &str, value: Option<&str>) -> bool {
        name == "TOLLGATE_INLINE_CAP"
            && value
                .and_then(|v| v.parse::<u64>().ok())
                .is_some_and(|n| n <= self.ctx.inline_cap)
    }

    /// The text a literal `echo`, `printf` or `cat <<EOF` writes to its
    /// stdout. An unquoted heredoc gives its body as written: its
    /// expansions stay as the same `$...` code, which the walk of that
    /// text then treats as words made at run time, and the rest is the
    /// code the shell that reads it runs.
    fn output(args: &[Arg], redirs: &[Redir]) -> Option<String> {
        let name = args.first()?.lit()?;
        let rest = &args[1..];
        match name {
            "cat" if rest.is_empty() => {
                let r = redirs.iter().rev().find(|r| r.feeds_stdin())?;
                if r.op != Op::Here {
                    return None;
                }
                let doc = r.doc.as_ref()?.borrow();
                Some(doc.literal().unwrap_or_else(|| doc.body.clone()))
            }
            "echo" => {
                let mut words: Vec<&str> = rest.iter().map(Arg::lit).collect::<Option<_>>()?;
                let mut escapes = false;
                while let Some(f) = words.first()
                    && matches!(*f, "-e" | "-n" | "-E" | "-ne" | "-en")
                {
                    escapes |= f.contains('e');
                    words.remove(0);
                }
                let t = words.join(" ");
                Some(if escapes { unescape(&t) } else { t } + "\n")
            }
            "printf" => {
                let words: Vec<String> = rest
                    .iter()
                    .map(|a| a.lit().map(unescape))
                    .collect::<Option<_>>()?;
                Some(words.join("\n"))
            }
            _ => None,
        }
    }

    /// Remembers the file a `>` or `>>` of this command writes, so a
    /// later `bash FILE` reads the new text and not the old file.
    fn record(&mut self, args: &[Arg], c: &Command, st: &State, raw: &str) {
        for r in &c.redirs {
            if !matches!(r.op, Op::Out | Op::Clobber | Op::Append)
                || r.fd.is_some_and(|f| f != 1)
                || r.var.is_some()
            {
                continue;
            }
            let t = self.arg(&r.target);
            let (Some(name), Some(cwd)) = (t.lit(), st.cwd.as_deref()) else {
                continue;
            };
            let path = paths::lexical(cwd, Path::new(name));
            let new = match Self::output(args, &c.redirs) {
                Some(text) => Written::Text(text),
                None => Written::Runtime(format!("{} {raw}", join(args))),
            };
            let old = self.written.remove(&path);
            let new = match (r.op == Op::Append, old, new) {
                (false, _, new) => new,
                (true, Some(Written::Text(a)), Written::Text(b)) => Written::Text(a + &b),
                (true, Some(a), b) => Written::Runtime(format!("{}\n{}", a.text(), b.text())),
                (true, None, b) => Written::Runtime(b.text().to_owned()),
            };
            self.written.insert(path, new);
        }
    }

    // ---- commands ----

    fn run(&mut self, args: &[Arg], st: &mut State, io: Io<'_>) {
        let Some(first) = args.first() else {
            return;
        };
        let rest = &args[1..];
        let Some(name) = first.lit() else {
            // Case 3: the command name is made at run time.
            if self.has_marker(&join(args))
                || matches!(git::check(self.ctx, rest).ruling, Ruling::Deny(_))
            {
                self.unclassified(3, "a command whose name is made at run time");
            } else {
                self.probe(rest, st, io, 3);
            }
            return;
        };
        let base = rules::basename(name);
        if base == "git" {
            return self.git(rest, st);
        }
        if rules::is_tollgate(self.ctx, name) {
            return self.tollgate(rest, st);
        }
        if cmds::is_shell(base) {
            return self.shell(rest, st, io);
        }
        match name {
            "eval" => {
                let text = join(rest);
                if rest.iter().all(|a| !a.dynamic) {
                    self.code(&text, st);
                } else {
                    self.runtime(&format!("{text} {}", io.raw));
                }
                return;
            }
            "source" | "." => {
                if let Some(f) = rest.first() {
                    self.run_file(f, st, false, true, io);
                }
                return;
            }
            "cd" | "pushd" => return self.cd(rest, st),
            "popd" => {
                st.cwd = None;
                return;
            }
            "export" | "declare" | "typeset" | "local" | "readonly" => {
                return self.declare(name, rest, st);
            }
            "unset" => {
                for a in rest.iter().filter(|a| !a.is_opt()) {
                    if config_var(&a.s) {
                        self.add(config_env_deny(&a.s, "`unset`"));
                    } else if taint_var(&a.s) {
                        st.taint = Some(a.s.clone());
                    } else if shell::is_name(&a.s) {
                        self.vars.insert(a.s.clone(), None);
                    }
                }
                return;
            }
            _ => {}
        }
        if let Some(w) = cmds::wrapper(base) {
            return self.wrapper(w, rest, st, io);
        }
        if let Some(r) = runners::runner(base, rest) {
            return self.runner(r, rest, st, io);
        }
        if let Some(targets) = cmds::write_targets(base, rest) {
            let how = format!("`{base}`");
            for (t, removal) in targets {
                self.write(&t, removal, &how, st.cwd.as_deref());
            }
            return;
        }
        if name.contains('/') {
            self.run_file(first, st, true, false, io);
        }
        if !cmds::takes_text(base) {
            self.probe(rest, st, io, 5);
        }
    }

    /// M2b, M2c: git or tollgate runs here.
    fn reached(&mut self, st: &State, what: &str) {
        if st.lost {
            self.add(Ruling::deny(
                "env-i",
                format!(
                    "{what} runs without the session environment (`env -i`, `env -u`, `exec -c` or `sudo`), so the hook injection is lost; run it without that wrapper (R25)"
                ),
            ));
        }
        if let Some(v) = &st.taint {
            self.add(Ruling::deny(
                "git-config-env",
                format!(
                    "`{v}` is set for a command that runs {what}: it changes the programs or the limits the gate uses; run {what} without it (R25)"
                ),
            ));
        }
    }

    fn git(&mut self, rest: &[Arg], st: &State) {
        let out = git::check(self.ctx, rest);
        if !rest.is_empty() {
            self.reached(st, "git");
        }
        self.long_timeout |= out.waits;
        self.add(out.ruling);
        if out.writes.is_empty() {
            return;
        }
        let mut cwd = st.cwd.clone();
        for d in &out.dirs {
            cwd = match (cwd, d.lit()) {
                (Some(c), Some(d)) => Some(paths::lexical(&c, Path::new(d))),
                _ => None,
            };
        }
        for (t, removal) in &out.writes {
            self.write(t, *removal, "`git`", cwd.as_deref());
        }
    }

    /// M4: the subcommands that only a person runs; R28 for the ones
    /// that wait.
    fn tollgate(&mut self, rest: &[Arg], st: &State) {
        let words: Vec<&str> = rest
            .iter()
            .filter(|a| !a.is_opt())
            .filter_map(Arg::lit)
            .collect();
        if !words.is_empty() {
            self.reached(st, "tollgate");
        }
        let person = match words.as_slice() {
            ["install", ..] => "install",
            ["uninstall", ..] => "uninstall",
            ["remotes", "forget", ..] => "remotes forget",
            ["baseline", "record", ..] => "baseline record",
            [sub, ..] => {
                self.long_timeout |= matches!(*sub, "check" | "wait" | "merge");
                return;
            }
            [] => return,
        };
        self.add(Ruling::deny(
            "person-only",
            format!(
                "`tollgate {person}` changes what the gate trusts; only a person runs it, in a terminal (R25)"
            ),
        ));
    }

    /// `sh`, `bash`, `zsh`, `dash`: the `-c` text, the script file, or
    /// the code on stdin.
    fn shell(&mut self, rest: &[Arg], st: &State, io: Io<'_>) {
        let mut i = 0;
        let mut stdin = false;
        while let Some(a) = rest.get(i) {
            let s = a.s.as_str();
            if a.dynamic || s.len() < 2 || !s.starts_with(['-', '+']) {
                break;
            }
            i += 1;
            if s == "--" {
                break;
            }
            if s.starts_with("--") {
                if matches!(s, "--rcfile" | "--init-file") {
                    i += 1;
                }
                continue;
            }
            let letters = &s[1..];
            if letters.ends_with(['o', 'O']) {
                i += 1;
            }
            if !s.starts_with('-') {
                continue;
            }
            if letters.contains('c') {
                let Some(code) = rest.get(i) else {
                    return;
                };
                match code.lit() {
                    Some(text) => self.code(text, &mut st.clone()),
                    None => self.runtime(&format!("{} {}", code.s, io.raw)),
                }
                return;
            }
            if letters.contains('n') {
                // `bash -n FILE` only checks the syntax.
                return;
            }
            stdin |= letters.contains('s');
        }
        match rest.get(i) {
            Some(f) if !stdin => self.run_file(f, &mut st.clone(), false, false, io),
            _ => self.stdin_code(st, io),
        }
    }

    /// The code a shell reads from its stdin: a heredoc, a here-string,
    /// a file, or the command before it in the pipeline.
    fn stdin_code(&mut self, st: &State, io: Io<'_>) {
        let mut sub = st.clone();
        if let Some(r) = io.redirs.iter().rev().find(|r| r.feeds_stdin()) {
            match r.op {
                Op::Here => {
                    let Some(doc) = &r.doc else {
                        return;
                    };
                    let doc = doc.borrow();
                    match doc.literal() {
                        Some(text) => self.code(&text, &mut sub),
                        None => self.runtime(&doc.body),
                    }
                }
                Op::HereStr => {
                    let a = self.arg(&r.target);
                    match a.lit() {
                        Some(text) => self.code(text, &mut sub),
                        None => self.runtime(&format!("{} {}", a.s, r.target.raw)),
                    }
                }
                Op::In => {
                    let a = self.arg(&r.target);
                    self.run_file(&a, &mut sub, false, false, io.detached());
                }
                _ => {}
            }
            return;
        }
        let Some(feeder) = io.feeder else {
            return;
        };
        let Kind::Simple(s) = &feeder.kind else {
            // A compound command writes the code: only the whole
            // command is known.
            let text = self.text;
            return self.runtime(text);
        };
        let args = self.words(&s.words);
        if let Some(text) = Self::output(&args, &feeder.redirs) {
            return self.code(&text, &mut sub);
        }
        if let [cat, file] = args.as_slice()
            && cat.lit() == Some("cat")
            && !file.is_opt()
        {
            return self.run_file(file, &mut sub, false, false, io.detached());
        }
        let raw: Vec<&str> = s.words.iter().map(|w| w.raw.as_str()).collect();
        self.runtime(&format!("{} {}", join(&args), raw.join(" ")));
    }

    /// Literal shell code: parse it and walk it.
    fn code(&mut self, text: &str, st: &mut State) {
        if st.nest >= MAX_NEST {
            return self.runtime(text);
        }
        match shell::parse(text) {
            Ok(script) => {
                st.nest += 1;
                self.script(&script, st);
                st.nest -= 1;
            }
            Err(_) => {
                if has_needle(text) {
                    self.unclassified(1, "shell code that does not parse as bash");
                }
            }
        }
    }

    fn cd(&mut self, rest: &[Arg], st: &mut State) {
        let i = operands_at(rest, &[]);
        st.cwd = match rest.get(i) {
            None => Some(self.ctx.home.clone()),
            Some(a) => match a.lit() {
                None | Some("-") => None,
                Some(p) if p.contains(['*', '?', '[']) => None,
                Some(p) if p.starts_with('/') => Some(paths::lexical(Path::new("/"), Path::new(p))),
                // bash looks in CDPATH first for a relative name.
                Some(p)
                    if !p.starts_with('.')
                        && self.lookup("CDPATH").is_some_and(|v| !v.is_empty()) =>
                {
                    None
                }
                Some(p) => st.cwd.as_ref().map(|c| paths::lexical(c, Path::new(p))),
            },
        };
    }

    /// `export`, `declare`, `typeset`, `local`, `readonly`.
    fn declare(&mut self, cmd: &str, rest: &[Arg], st: &mut State) {
        let exports = cmd == "export"
            || rest
                .iter()
                .any(|a| a.is_opt() && !a.s.starts_with("--") && a.s.contains('x'));
        for a in rest.iter().filter(|a| !a.is_opt()) {
            let (name, value) = match a.s.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (a.s.as_str(), None),
            };
            if !shell::is_name(name) {
                continue;
            }
            let value = value.map(|v| (!a.dynamic).then(|| v.to_owned()));
            if config_var(name) {
                self.add(config_env_deny(name, &format!("`{cmd}`")));
            } else if taint_var(name) {
                if exports
                    && let Some(v) = &value
                    && !self.cap_ok(name, v.as_deref())
                {
                    st.taint = Some(name.to_owned());
                }
            } else if let Some(v) = value {
                self.vars.insert(name.to_owned(), v);
            }
        }
    }

    fn wrapper(&mut self, w: Wrapper, rest: &[Arg], st: &mut State, io: Io<'_>) {
        let from = |i: usize| rest.get(i..).unwrap_or(&[]);
        let mut sub = st.clone();
        match w {
            Wrapper::Env => self.env(rest, &mut sub, io),
            Wrapper::Command => {
                if !rest
                    .first()
                    .is_some_and(|a| matches!(a.s.as_str(), "-v" | "-V"))
                {
                    self.run(from(operands_at(rest, &[])), st, io);
                }
            }
            Wrapper::Exec => {
                let mut i = 0;
                while let Some(a) = rest.get(i).filter(|a| !a.dynamic && a.is_opt()) {
                    i += 1;
                    sub.lost |= a.s.contains('c');
                    if a.s.ends_with('a') {
                        i += 1;
                    }
                }
                self.run(from(i), &mut sub, io);
            }
            Wrapper::Sudo => {
                let i = operands_at(rest, cmds::SUDO_VALUED);
                let keeps = rest[..i].iter().any(|a| {
                    a.s.starts_with("--preserve-env")
                        || (!a.s.starts_with("--") && a.s.contains('E'))
                });
                sub.lost |= !keeps;
                self.run(from(i), &mut sub, io);
            }
            Wrapper::Timeout => {
                let i = operands_at(rest, cmds::TIMEOUT_VALUED);
                self.run(from(i + 1), &mut sub, io);
            }
            Wrapper::Plain(valued) => self.run(from(operands_at(rest, valued)), &mut sub, io),
            Wrapper::Xargs => {
                let i = operands_at(rest, cmds::XARGS_VALUED);
                self.run(from(i), &mut sub, io.detached());
            }
            Wrapper::Find => self.find(rest, &sub, io),
        }
    }

    /// `env [options] [NAME=VALUE]... command`.
    fn env(&mut self, rest: &[Arg], st: &mut State, io: Io<'_>) {
        let chdir = |st: &mut State, dir: Option<&str>| {
            st.cwd = match (&st.cwd, dir) {
                (Some(c), Some(d)) => Some(paths::lexical(c, Path::new(d))),
                _ => None,
            };
        };
        let mut i = 0;
        while let Some(a) = rest.get(i) {
            let s = a.s.as_str();
            i += 1;
            if matches!(s, "-" | "-i" | "--ignore-environment") {
                st.lost = true;
            } else if s == "--" {
                break;
            } else if matches!(s, "-u" | "--unset") {
                st.lost |= rest.get(i).is_some_and(|n| config_var(&n.s));
                i += 1;
            } else if let Some(n) = s.strip_prefix("--unset=") {
                st.lost |= config_var(n);
            } else if matches!(s, "-C" | "--chdir") {
                chdir(st, rest.get(i).and_then(Arg::lit));
                i += 1;
            } else if let Some(d) = s.strip_prefix("--chdir=") {
                chdir(st, (!a.dynamic).then_some(d));
            } else if matches!(s, "-S" | "--split-string") || s.starts_with("--split-string=") {
                let (text, next) = match s.strip_prefix("--split-string=") {
                    Some(t) => (
                        Some(Arg {
                            s: t.to_owned(),
                            dynamic: a.dynamic,
                        }),
                        i,
                    ),
                    None => (rest.get(i).cloned(), i + 1),
                };
                let Some(text) = text else {
                    return;
                };
                let Some(text) = text.lit() else {
                    return self.runtime(&format!("{} {}", text.s, io.raw));
                };
                let mut inner: Vec<Arg> = text.split_whitespace().map(Arg::fixed).collect();
                inner.extend_from_slice(rest.get(next..).unwrap_or(&[]));
                return self.env(&inner, st, io);
            } else if !a.dynamic && a.is_opt() {
                if !s.starts_with("--") {
                    // A cluster: `-iv`, `-uNAME`, `-u NAME`, `-C dir`.
                    let valued = s.find(['u', 'C']).unwrap_or(s.len());
                    st.lost |= s[..valued].contains('i');
                    if valued < s.len() {
                        let attached = &s[valued + 1..];
                        let value = if attached.is_empty() {
                            i += 1;
                            rest.get(i - 1).map_or("", |n| n.s.as_str())
                        } else {
                            attached
                        };
                        if s[valued..].starts_with('u') {
                            st.lost |= config_var(value);
                        } else {
                            st.cwd = None;
                        }
                    }
                }
            } else if let Some((name, value)) = s.split_once('=')
                && shell::is_name(name)
            {
                if config_var(name) {
                    self.add(config_env_deny(name, "`env`"));
                } else if taint_var(name) && !self.cap_ok(name, (!a.dynamic).then_some(value)) {
                    st.taint = Some(name.to_owned());
                }
            } else {
                i -= 1;
                break;
            }
        }
        self.run(rest.get(i..).unwrap_or(&[]), st, io);
    }

    /// `find`: the commands of `-exec` and `-execdir`, and `-delete`.
    fn find(&mut self, rest: &[Arg], st: &State, io: Io<'_>) {
        let n = rest
            .iter()
            .position(|a| a.s.starts_with('-') || a.s == "(" || a.s == "!")
            .unwrap_or(rest.len());
        let starts = &rest[..n];
        let mut i = n;
        while i < rest.len() {
            match rest[i].lit() {
                Some(op @ ("-exec" | "-execdir" | "-ok" | "-okdir")) => {
                    let end = rest[i + 1..]
                        .iter()
                        .position(|a| matches!(a.lit(), Some(";" | "+")))
                        .map_or(rest.len(), |k| i + 1 + k);
                    // `{}` is a path under a start dir.
                    let inner: Vec<Arg> = rest[i + 1..end]
                        .iter()
                        .map(|a| match starts {
                            [one] if a.s == "{}" => Arg {
                                s: format!("{}/{DYNAMIC}", one.s.trim_end_matches('/')),
                                dynamic: true,
                            },
                            _ => a.clone(),
                        })
                        .collect();
                    let mut sub = st.clone();
                    if op.ends_with("dir") {
                        sub.cwd = None;
                    }
                    self.run(&inner, &mut sub, io.detached());
                    i = end;
                }
                Some("-delete") => {
                    for p in starts {
                        self.write(p, true, "`find -delete`", st.cwd.as_deref());
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn runner(&mut self, r: Runner, rest: &[Arg], st: &State, io: Io<'_>) {
        match r {
            Runner::Argv(i) => self.run(rest.get(i..).unwrap_or(&[]), &mut st.clone(), io),
            Runner::Script(name) => {
                let Some(cwd) = &st.cwd else {
                    return;
                };
                let Some(text) = self.read(&cwd.join("package.json")) else {
                    return;
                };
                let script = serde_json::from_str::<serde_json::Value>(&text.0)
                    .ok()
                    .and_then(|v| v["scripts"][name.as_str()].as_str().map(str::to_owned));
                // A script that names nothing can still run a script file
                // that does, as in `run_file`.
                if let Some(code) = script {
                    self.code(&code, &mut st.clone());
                }
            }
            Runner::Data => {}
        }
    }

    /// Case 5 (and the arguments of case 3): the words of an unknown
    /// program, from the first one that names git, tollgate or a shell,
    /// read as a command. A rule that refuses that command asks here.
    fn probe(&mut self, rest: &[Arg], st: &State, io: Io<'_>, case: u8) {
        let Some(k) = rest.iter().position(|a| {
            a.lit().is_some_and(|s| {
                let b = rules::basename(s);
                b == "git" || s == "tollgate" || cmds::is_shell(b)
            })
        }) else {
            return;
        };
        let outer = std::mem::replace(&mut self.ruling, Ruling::Allow);
        self.run(&rest[k..], &mut st.clone(), io.detached());
        let inner = std::mem::replace(&mut self.ruling, outer);
        if let Some(r) = inner.reason() {
            self.add(Ruling::ask(
                "unclassified",
                format!(
                    "a program the guard does not know gets a command in its arguments that a rule refuses ({}): {}; a person decides (R26, case {case})",
                    r.rule, r.why
                ),
            ));
        }
    }

    // ---- files ----

    /// Reads `path` inside the budget: the text, and "the budget cut it".
    fn read(&mut self, path: &Path) -> Option<(String, bool)> {
        if self.files >= MAX_FILES || !path.is_file() {
            return None;
        }
        self.files += 1;
        let left = MAX_BYTES.saturating_sub(self.bytes);
        let mut buf = Vec::new();
        std::fs::File::open(path)
            .ok()?
            .take(left as u64 + 1)
            .read_to_end(&mut buf)
            .ok()?;
        let cut = buf.len() > left;
        buf.truncate(left);
        self.bytes += buf.len();
        if buf.contains(&0) {
            return None;
        }
        Some((String::from_utf8_lossy(&buf).into_owned(), cut))
    }

    /// A script file that a shell runs: `bash F`, `source F`, `./F`
    /// (`direct`). `keep`: it runs in this shell, so what it changes
    /// stays.
    fn run_file(&mut self, f: &Arg, st: &mut State, direct: bool, keep: bool, io: Io<'_>) {
        let Some(name) = f.lit() else {
            // Only a process substitution makes the code itself at run
            // time; a file at a path made at run time cannot be read.
            if io.raw.contains("<(") {
                self.runtime(&format!("{} {}", f.s, io.raw));
            }
            return;
        };
        if name == "/dev/stdin" {
            return self.stdin_code(st, io);
        }
        if name.starts_with("/dev/") || name.starts_with("/proc/") {
            return;
        }
        let Some(cwd) = st
            .cwd
            .clone()
            .or_else(|| name.starts_with('/').then(PathBuf::new))
        else {
            return;
        };
        let path = paths::lexical(&cwd, Path::new(name));
        let (text, cut) = match self.written.get(&path).cloned() {
            Some(Written::Text(t)) => (t, false),
            Some(Written::Runtime(t)) => return self.runtime(&t),
            None => match self.read(&path) {
                Some(r) => r,
                None => return,
            },
        };
        if direct {
            // The kernel runs another interpreter: the file is data.
            if let Some(line) = text.strip_prefix("#!") {
                let mut words = line.lines().next().unwrap_or("").split_whitespace();
                let mut interp = rules::basename(words.next().unwrap_or(""));
                if interp == "env" {
                    interp = words.find(|w| !w.starts_with('-')).unwrap_or("");
                }
                if !cmds::is_shell(rules::basename(interp)) {
                    return;
                }
            } else if path
                .extension()
                .is_some_and(|e| !matches!(e.to_str(), Some("sh" | "bash" | "zsh")))
            {
                return;
            }
        }
        // A script that names nothing can still run a script that does.
        let script = if cut || st.depth >= MAX_DEPTH {
            None
        } else {
            shell::parse(&text).ok()
        };
        let Some(script) = script else {
            // Case 4.
            if has_needle(&text) && self.has_marker(&text) {
                self.unclassified(4, &format!("the script file {}", path.display()));
            }
            return;
        };
        let mut sub = st.clone();
        sub.depth += 1;
        self.script(&script, &mut sub);
        if keep {
            sub.depth -= 1;
            *st = sub;
        }
    }

    /// M3: a file that a redirection or an ordinary tool writes.
    fn write(&mut self, t: &Arg, removal: bool, how: &str, cwd: Option<&Path>) {
        let s = t.s.as_str();
        if s.is_empty() || s == "-" || s.starts_with("/dev/") {
            return;
        }
        let abs = |text: &str| -> Option<PathBuf> {
            if text.starts_with('/') {
                Some(paths::lexical(Path::new("/"), Path::new(text)))
            } else {
                cwd.map(|c| paths::lexical(c, Path::new(text)))
            }
        };
        if t.dynamic {
            // The dir that the literal start of the word names.
            let end = s.find([DYNAMIC, '{']).unwrap_or(s.len());
            let dir = s[..end].rfind('/').map(|k| &s[..=k]);
            if let Some(p) = dir.and_then(abs)
                && let Some(d) = paths::tollgate_dir(self.ctx, &p, false)
            {
                return self.add(Ruling::deny(
                    "state-dir-write",
                    format!(
                        "{how} writes under tollgate's dir {}: records, jobs and the installed hooks are only written by tollgate (R25)",
                        d.display()
                    ),
                ));
            }
            if self.path_marker(s) {
                self.unclassified(
                    6,
                    &format!("{how} writes a path with a part made at run time"),
                );
            }
            return;
        }
        let Some(path) = abs(s) else {
            if self.path_marker(s) {
                self.unclassified(
                    6,
                    &format!("{how} writes a path under a dir the guard cannot follow"),
                );
            }
            return;
        };
        let mut ruling = rules::write_ruling(self.ctx, &path, removal, how);
        if s.contains(['*', '?', '[']) {
            ruling = ruling.max(self.glob_write(&path, removal, how));
            if ruling == Ruling::Allow && self.path_marker(s) {
                self.unclassified(6, &format!("{how} writes a path with a pattern"));
            }
        }
        self.add(ruling);
    }

    /// A pattern in a component at or above a tollgate dir
    /// (`rm -rf ~/.local/state/toll*`): the rule for the dir it matches.
    fn glob_write(&self, path: &Path, removal: bool, how: &str) -> Ruling {
        let comps: Vec<String> = path
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        let Some(k) = comps.iter().position(|c| c.contains(['*', '?', '['])) else {
            return Ruling::Allow;
        };
        let mut out = Ruling::Allow;
        for dir in &self.ctx.protected {
            let d: Vec<String> = dir
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect();
            if k < d.len() && comps[..k] == d[..k] && wild(comps[k].as_bytes(), d[k].as_bytes()) {
                let hit: PathBuf = d[..=k].iter().chain(&comps[k + 1..]).collect();
                out = out.max(rules::write_ruling(self.ctx, &hit, removal, how));
            }
        }
        out
    }
}
