//! A bash parser for the guard's walker (R25, R26).
//!
//! It builds the command tree bash would run: lists, and-or lists,
//! pipelines, simple commands, subshells, groups, `if`, `while`, `until`,
//! `for`, `select`, `case`, `[[ ]]`, `(( ))` and function definitions,
//! with their redirections and heredocs. Words keep their parts (literal
//! text, quotes, parameters, substitutions, globs, tilde, brace
//! expansion), so the rules can tell a literal word from one bash builds at
//! run time. Command and process substitutions are parsed in place, as
//! bash 5 does, so a heredoc or a quote inside `$(...)` cannot move the
//! end of the substitution.
//!
//! The parser is strict: input it does not model (an unterminated quote,
//! `coproc`, extended globs, a stray `(`) is a [`ParseError`]. The walker
//! then asks when the text names git, tollgate or `.claude`, and allows
//! it otherwise. ANSI-C strings (`$'...'`) are found as bash finds them
//! (a backslash escapes the next character) and kept undecoded.

use std::cell::RefCell;
use std::rc::Rc;

/// Input the parser does not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One part of a word.
#[derive(Debug, Clone)]
pub enum Part {
    /// Unquoted text, backslash escapes removed.
    Lit(String),
    /// `'...'`.
    Single(String),
    /// `"..."` (also `$"..."`): literal text, parameters, substitutions.
    Double(Vec<Part>),
    /// `$'...'`, undecoded.
    AnsiC(String),
    /// `$name`, `$1`, `${...}`: the text after `$` (braces kept), and the
    /// commands any substitution inside it runs.
    Param(String, Vec<Script>),
    /// `$(...)`.
    CmdSub(Script),
    /// `` `...` ``.
    Backtick(Script),
    /// `$((...))`: the expression and the commands substitutions inside it
    /// run.
    Arith(String, Vec<Script>),
    /// `<(...)` or `>(...)`.
    ProcSub(Script),
    /// An unquoted `*`, `?` or `[` (pathname expansion).
    Glob(char),
    /// An unquoted `~` or `~user` at the start of a word or value.
    Tilde(String),
}

/// A word: its parts, whether bash brace-expands it, and its source text.
#[derive(Debug, Clone, Default)]
pub struct Word {
    pub parts: Vec<Part>,
    /// An unquoted `{...,...}` or `{a..b}`: bash makes several words.
    pub brace: bool,
    /// The source text.
    pub raw: String,
}

impl Word {
    /// The word bash passes when every part is fixed text: literal text,
    /// quotes with literal text inside, and the heredoc message idiom
    /// `"$(cat <<'EOF' ... EOF)"` (inside double quotes only: unquoted, its
    /// output would be split into words). `None` otherwise.
    #[must_use]
    pub fn literal(&self) -> Option<String> {
        self.value(&|_| None, None)
    }

    /// [`Self::literal`] with `~` and `~/` resolved to `home`.
    #[must_use]
    pub fn literal_home(&self, home: &str) -> Option<String> {
        self.value(&|_| None, Some(home))
    }

    /// The word with simple parameters (`$NAME`, `${NAME}`) taken from
    /// `lookup` and `~` from `home`; `None` when anything else is in it.
    #[must_use]
    pub fn value(
        &self,
        lookup: &dyn Fn(&str) -> Option<String>,
        home: Option<&str>,
    ) -> Option<String> {
        if self.brace {
            return None;
        }
        let mut out = String::new();
        for (k, p) in self.parts.iter().enumerate() {
            match p {
                Part::Lit(s) | Part::Single(s) => out.push_str(s),
                Part::Double(inner) => {
                    for q in inner {
                        match q {
                            Part::Lit(s) => out.push_str(s),
                            Part::CmdSub(s) => out.push_str(&s.cat_heredoc()?),
                            Part::Param(name, subs) if subs.is_empty() => {
                                out.push_str(&lookup(simple_param(name)?)?);
                            }
                            _ => return None,
                        }
                    }
                }
                Part::Param(name, subs) if subs.is_empty() => {
                    // Unquoted: word splitting; only a value without blanks
                    // or glob characters stays one word.
                    let v = lookup(simple_param(name)?)?;
                    if v.is_empty() || v.contains([' ', '\t', '\n', '*', '?', '[']) {
                        return None;
                    }
                    out.push_str(&v);
                }
                Part::Tilde(user) if k == 0 && user.is_empty() => out.push_str(home?),
                _ => return None,
            }
        }
        Some(out)
    }

    /// True when the word has no parts that run code or expand at run
    /// time, except simple parameters (`$x`, `"${x}"`): the words of a
    /// non-gated command whose values do not matter.
    #[must_use]
    pub fn is_plain(&self) -> bool {
        self.literal().is_some()
    }

    /// Every script that runs while bash builds the word.
    #[must_use]
    pub fn scripts(&self) -> Vec<&Script> {
        let mut out = Vec::new();
        collect_scripts(&self.parts, &mut out);
        out
    }

    /// The literal text before the first non-literal part (quotes
    /// removed), and whether the whole word is literal.
    #[must_use]
    pub fn literal_prefix(&self) -> (String, bool) {
        let mut out = String::new();
        for p in &self.parts {
            match p {
                Part::Lit(s) | Part::Single(s) => out.push_str(s),
                Part::Double(inner) => {
                    for q in inner {
                        match q {
                            Part::Lit(s) => out.push_str(s),
                            _ => return (out, false),
                        }
                    }
                }
                _ => return (out, false),
            }
        }
        (out, !self.brace)
    }
}

/// `NAME` of `$NAME` or `${NAME}` (no operators); `None` otherwise.
pub(super) fn simple_param(text: &str) -> Option<&str> {
    let name = text
        .strip_prefix('{')
        .and_then(|t| t.strip_suffix('}'))
        .unwrap_or(text);
    is_name(name).then_some(name)
}

/// Every script that runs while bash expands `parts` (a heredoc body, an
/// arithmetic header).
#[must_use]
pub(super) fn part_scripts(parts: &[Part]) -> Vec<&Script> {
    let mut out = Vec::new();
    collect_scripts(parts, &mut out);
    out
}

fn collect_scripts<'a>(parts: &'a [Part], out: &mut Vec<&'a Script>) {
    for p in parts {
        match p {
            Part::Double(inner) => collect_scripts(inner, out),
            Part::Param(_, s) | Part::Arith(_, s) => out.extend(s.iter()),
            Part::CmdSub(s) | Part::Backtick(s) | Part::ProcSub(s) => out.push(s),
            _ => {}
        }
    }
}

/// A list: and-or lists separated by `;`, `&` or newlines.
#[derive(Debug, Clone, Default)]
pub struct Script {
    pub items: Vec<AndOr>,
}

impl Script {
    /// The text `$(...)` of this script gives when it is exactly
    /// `cat <<'EOF' ... EOF` (a quoted delimiter, or a body with no
    /// expansion): the body without its trailing newlines.
    #[must_use]
    pub fn cat_heredoc(&self) -> Option<String> {
        let [ao] = self.items.as_slice() else {
            return None;
        };
        if !ao.rest.is_empty() || ao.background || ao.first.negate {
            return None;
        }
        let [c] = ao.first.cmds.as_slice() else {
            return None;
        };
        let Kind::Simple(s) = &c.kind else {
            return None;
        };
        let [w] = s.words.as_slice() else {
            return None;
        };
        if !s.assigns.is_empty() || w.literal().as_deref() != Some("cat") {
            return None;
        }
        let [r] = c.redirs.as_slice() else {
            return None;
        };
        if r.op != Op::Here || r.fd.is_some_and(|f| f != 0) {
            return None;
        }
        let body = r.doc.as_ref()?.borrow().literal()?;
        Some(body.trim_end_matches('\n').to_owned())
    }
}

/// Pipelines joined by `&&` and `||`.
#[derive(Debug, Clone)]
pub struct AndOr {
    pub first: Pipeline,
    /// `(true, p)` for `&& p`, `(false, p)` for `|| p`.
    pub rest: Vec<(bool, Pipeline)>,
    /// Ended by `&`.
    pub background: bool,
}

/// Commands joined by `|` or `|&`.
#[derive(Debug, Clone)]
pub struct Pipeline {
    pub negate: bool,
    pub cmds: Vec<Command>,
}

/// A command with its redirections.
#[derive(Debug, Clone)]
pub struct Command {
    pub kind: Kind,
    pub redirs: Vec<Redir>,
}

/// The kinds of command.
#[derive(Debug, Clone)]
pub enum Kind {
    Simple(Simple),
    Subshell(Script),
    Group(Script),
    If {
        arms: Vec<(Script, Script)>,
        other: Option<Script>,
    },
    /// `while` and `until`.
    Loop {
        cond: Script,
        body: Script,
    },
    /// `for` and `select`; `var` as written.
    For {
        var: Word,
        items: Option<Vec<Word>>,
        body: Script,
    },
    /// `for ((...))`.
    ArithFor {
        header: Part,
        body: Script,
    },
    Case {
        subject: Word,
        arms: Vec<(Vec<Word>, Script)>,
    },
    Func {
        name: Word,
        body: Box<Command>,
    },
    /// `[[ ... ]]`.
    Cond(Vec<Word>),
    /// `(( ... ))`.
    Arith(Part),
}

/// Assignments, then the command name and its arguments.
#[derive(Debug, Clone, Default)]
pub struct Simple {
    pub assigns: Vec<Assign>,
    pub words: Vec<Word>,
}

/// `NAME=value`, `NAME+=value`, `NAME[i]=value` or `NAME=(a b)`.
#[derive(Debug, Clone)]
pub struct Assign {
    pub name: String,
    /// The value (one word), or the items of an array value.
    pub value: Vec<Word>,
    pub array: bool,
    /// The whole assignment as written.
    pub raw: String,
}

/// A redirection operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `<`
    In,
    /// `>`
    Out,
    /// `>>`
    Append,
    /// `>|`
    Clobber,
    /// `<>`
    ReadWrite,
    /// `<<` and `<<-`
    Here,
    /// `<<<`
    HereStr,
    /// `<&`
    DupIn,
    /// `>&`
    DupOut,
    /// `&>`
    OutErr,
    /// `&>>`
    AppendErr,
}

/// One redirection.
#[derive(Debug, Clone)]
pub struct Redir {
    /// An explicit fd number (`2>`).
    pub fd: Option<u32>,
    /// `{NAME}>`: bash opens a new fd and assigns its number to `NAME`.
    pub var: Option<String>,
    pub op: Op,
    /// The file, fd, here-string, or heredoc delimiter.
    pub target: Word,
    /// The heredoc body, read at the next newline.
    pub doc: Option<Rc<RefCell<Doc>>>,
}

impl Redir {
    /// True when the redirection reads the command's stdin (fd 0).
    #[must_use]
    pub fn feeds_stdin(&self) -> bool {
        matches!(
            self.op,
            Op::In | Op::ReadWrite | Op::Here | Op::HereStr | Op::DupIn
        ) && self.fd.unwrap_or(0) == 0
            && self.var.is_none()
    }

    /// True when the redirection writes a file named by its target.
    #[must_use]
    pub fn writes_file(&self) -> bool {
        match self.op {
            Op::Out | Op::Append | Op::Clobber | Op::ReadWrite | Op::OutErr | Op::AppendErr => true,
            // `>&file` (not an fd number or `-`) writes the file.
            Op::DupOut => self.target.literal().is_none_or(|t| {
                !(t == "-" || (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())))
            }),
            _ => false,
        }
    }
}

/// A heredoc body.
#[derive(Debug, Clone, Default)]
pub struct Doc {
    /// The delimiter was quoted: the body is literal.
    pub quoted: bool,
    pub body: String,
    /// For an unquoted delimiter: the body's parts after expansion
    /// (parameters, substitutions).
    pub parts: Vec<Part>,
}

impl Doc {
    /// The body as the command reads it, when nothing in it expands.
    #[must_use]
    pub fn literal(&self) -> Option<String> {
        if self.quoted {
            return Some(self.body.clone());
        }
        let mut out = String::new();
        for p in &self.parts {
            match p {
                Part::Lit(s) => out.push_str(s),
                _ => return None,
            }
        }
        Some(out)
    }
}

/// True for a shell variable name.
#[must_use]
pub fn is_name(s: &str) -> bool {
    let mut c = s.chars();
    c.next()
        .is_some_and(|f| f.is_ascii_alphabetic() || f == '_')
        && c.all(|f| f.is_ascii_alphanumeric() || f == '_')
}

/// Words that end an unquoted word.
fn is_meta(c: char) -> bool {
    matches!(
        c,
        ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' | '<' | '>'
    )
}

/// How deep lists, substitutions and quotes may nest.
const MAX_DEPTH: usize = 64;

/// Parses a Bash command.
///
/// # Errors
/// Input bash would reject or the guard does not model.
pub fn parse(src: &str) -> Result<Script, ParseError> {
    parse_at(src, 0)
}

fn parse_at(src: &str, depth: usize) -> Result<Script, ParseError> {
    let mut p = Parser {
        s: src.chars().collect(),
        i: 0,
        pending: Vec::new(),
        depth,
    };
    let script = p.list(&End::Eof)?;
    if p.i < p.s.len() {
        return Err(p.err("unexpected text"));
    }
    // A heredoc with no newline after its line: bash reads an empty body.
    p.pending.clear();
    Ok(script)
}

/// Where a list ends.
enum End {
    Eof,
    /// `)` of a subshell or substitution.
    Paren,
    /// One of these reserved words in command position.
    Words(&'static [&'static str]),
    /// A case arm: `;;`, `;&`, `;;&` or `esac`.
    CaseArm,
}

struct Parser {
    s: Vec<char>,
    i: usize,
    /// Heredocs whose bodies start after the next newline.
    pending: Vec<(String, bool, Rc<RefCell<Doc>>)>,
    depth: usize,
}

type R<T> = Result<T, ParseError>;

impl Parser {
    fn err(&self, what: &str) -> ParseError {
        let near: String = self.s.iter().skip(self.i).take(24).collect();
        ParseError(format!("{what} near `{}`", near.replace('\n', "\\n")))
    }

    fn peek(&self) -> Option<char> {
        self.s.get(self.i).copied()
    }

    fn at(&self, n: usize) -> Option<char> {
        self.s.get(self.i + n).copied()
    }

    fn starts(&self, t: &str) -> bool {
        t.chars().enumerate().all(|(k, c)| self.at(k) == Some(c))
    }

    fn deeper(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(self.err("nested too deeply"));
        }
        Ok(())
    }

    /// Skips blanks, line continuations and a comment (not the newline).
    fn blanks(&mut self) {
        loop {
            match self.peek() {
                Some(' ' | '\t') => self.i += 1,
                Some('\\') if self.at(1) == Some('\n') => self.i += 2,
                Some('#') => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.i += 1;
                    }
                }
                _ => return,
            }
        }
    }

    /// Skips blanks, comments and newlines; reads heredoc bodies.
    fn blanks_nl(&mut self) -> R<()> {
        loop {
            self.blanks();
            if self.peek() == Some('\n') {
                self.i += 1;
                self.heredocs()?;
            } else {
                return Ok(());
            }
        }
    }

    /// Reads the bodies of the pending heredocs (after a newline).
    fn heredocs(&mut self) -> R<()> {
        for (delim, strip, doc) in std::mem::take(&mut self.pending) {
            let mut body = String::new();
            loop {
                if self.peek().is_none() {
                    break;
                }
                let start = self.i;
                while self.peek().is_some_and(|c| c != '\n') {
                    self.i += 1;
                }
                let mut line: String = self.s[start..self.i].iter().collect();
                if self.peek() == Some('\n') {
                    self.i += 1;
                }
                if strip {
                    line = line.trim_start_matches('\t').to_owned();
                }
                if line == delim {
                    break;
                }
                body.push_str(&line);
                body.push('\n');
            }
            let mut d = doc.borrow_mut();
            if !d.quoted {
                d.parts = expand_doc(&body, self.depth + 1)?;
            }
            d.body = body;
        }
        Ok(())
    }

    /// The plain word at the cursor (no quotes or expansions) when it is
    /// followed by a metacharacter or the end: for reserved words.
    fn plain_word(&self) -> Option<String> {
        let mut k = self.i;
        let mut w = String::new();
        while let Some(&c) = self.s.get(k) {
            if is_meta(c) {
                break;
            }
            if matches!(c, '\'' | '"' | '\\' | '$' | '`') {
                return None;
            }
            w.push(c);
            k += 1;
        }
        (!w.is_empty()).then_some(w)
    }

    fn take_word(&mut self, w: &str) -> bool {
        if self.plain_word().as_deref() == Some(w) {
            self.i += w.chars().count();
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self, w: &str) -> R<()> {
        self.blanks_nl()?;
        if self.take_word(w) {
            Ok(())
        } else {
            Err(self.err(&format!("expected `{w}`")))
        }
    }

    fn at_end(&self, end: &End) -> bool {
        match end {
            End::Eof => self.peek().is_none(),
            End::Paren => self.peek() == Some(')'),
            End::Words(ws) => self.plain_word().is_some_and(|w| ws.contains(&w.as_str())),
            End::CaseArm => {
                self.starts(";;")
                    || self.starts(";&")
                    || self.plain_word().as_deref() == Some("esac")
            }
        }
    }

    fn list(&mut self, end: &End) -> R<Script> {
        self.deeper()?;
        let mut items: Vec<AndOr> = Vec::new();
        loop {
            self.blanks_nl()?;
            if self.at_end(end) {
                break;
            }
            if self.peek().is_none() {
                return Err(self.err("unexpected end of input"));
            }
            let ao = self.and_or()?;
            items.push(ao);
            self.blanks();
            match self.peek() {
                Some(';') if !self.starts(";;") && !self.starts(";&") => self.i += 1,
                Some('&') if !self.starts("&&") && !self.starts("&>") => {
                    self.i += 1;
                    if let Some(last) = items.last_mut() {
                        last.background = true;
                    }
                }
                Some('\n') | None => {}
                _ if self.at_end(end) => {}
                _ => return Err(self.err("unexpected text after a command")),
            }
        }
        self.depth -= 1;
        Ok(Script { items })
    }

    fn and_or(&mut self) -> R<AndOr> {
        let first = self.pipeline()?;
        let mut rest = Vec::new();
        loop {
            self.blanks();
            let and = if self.starts("&&") {
                true
            } else if self.starts("||") {
                false
            } else {
                break;
            };
            self.i += 2;
            self.blanks_nl()?;
            rest.push((and, self.pipeline()?));
        }
        Ok(AndOr {
            first,
            rest,
            background: false,
        })
    }

    fn pipeline(&mut self) -> R<Pipeline> {
        let mut negate = false;
        loop {
            self.blanks();
            if self.take_word("!") {
                negate = !negate;
            } else if self.take_word("time") {
                self.blanks();
                self.take_word("-p");
            } else {
                break;
            }
        }
        let mut cmds = vec![self.command()?];
        loop {
            self.blanks();
            if self.peek() == Some('|') && self.at(1) != Some('|') {
                self.i += 1;
                if self.peek() == Some('&') {
                    self.i += 1;
                }
                self.blanks_nl()?;
                cmds.push(self.command()?);
            } else {
                break;
            }
        }
        Ok(Pipeline { negate, cmds })
    }

    fn command(&mut self) -> R<Command> {
        self.blanks();
        let kind = match self.plain_word().as_deref() {
            _ if self.starts("((") => match self.arith(2)? {
                Some(a) => Kind::Arith(a),
                None => {
                    self.i += 1;
                    Kind::Subshell(self.sub_list()?)
                }
            },
            _ if self.peek() == Some('(') => {
                self.i += 1;
                Kind::Subshell(self.sub_list()?)
            }
            Some("if") => self.if_cmd()?,
            Some("while" | "until") => {
                self.i += 5;
                let cond = self.list(&End::Words(&["do"]))?;
                self.expect_word("do")?;
                let body = self.list(&End::Words(&["done"]))?;
                self.expect_word("done")?;
                Kind::Loop { cond, body }
            }
            Some("for" | "select") => self.for_cmd()?,
            Some("case") => self.case_cmd()?,
            Some("{") => {
                self.i += 1;
                let body = self.list(&End::Words(&["}"]))?;
                self.expect_word("}")?;
                Kind::Group(body)
            }
            Some("[[") => self.cond_cmd()?,
            Some("function") => {
                self.i += "function".len();
                self.blanks();
                let name = self.word()?;
                self.blanks();
                if self.peek() == Some('(') {
                    self.i += 1;
                    self.blanks();
                    if self.peek() != Some(')') {
                        return Err(self.err("expected `)`"));
                    }
                    self.i += 1;
                }
                self.blanks_nl()?;
                Kind::Func {
                    name,
                    body: Box::new(self.command()?),
                }
            }
            Some(
                "coproc" | "then" | "elif" | "else" | "fi" | "do" | "done" | "esac" | "}" | "in"
                | "]]",
            ) => return Err(self.err("unsupported or misplaced reserved word")),
            _ => return self.simple(),
        };
        let redirs = self.redirs()?;
        Ok(Command { kind, redirs })
    }

    /// The list of a subshell or substitution, after `(`, through `)`.
    fn sub_list(&mut self) -> R<Script> {
        let s = self.list(&End::Paren)?;
        if self.peek() != Some(')') {
            return Err(self.err("expected `)`"));
        }
        self.i += 1;
        Ok(s)
    }

    fn redirs(&mut self) -> R<Vec<Redir>> {
        let mut out = Vec::new();
        loop {
            self.blanks();
            if !self.at_redir() {
                return Ok(out);
            }
            out.push(self.redir()?);
        }
    }

    fn if_cmd(&mut self) -> R<Kind> {
        self.i += 2;
        let mut arms = Vec::new();
        let mut other = None;
        loop {
            let cond = self.list(&End::Words(&["then"]))?;
            self.expect_word("then")?;
            let body = self.list(&End::Words(&["elif", "else", "fi"]))?;
            arms.push((cond, body));
            self.blanks_nl()?;
            if self.take_word("elif") {
                continue;
            }
            if self.take_word("else") {
                other = Some(self.list(&End::Words(&["fi"]))?);
            }
            self.expect_word("fi")?;
            return Ok(Kind::If { arms, other });
        }
    }

    fn for_cmd(&mut self) -> R<Kind> {
        let kw = self.plain_word().unwrap_or_default();
        self.i += kw.len();
        self.blanks();
        if kw == "for" && self.starts("((") {
            let header = self
                .arith(2)?
                .ok_or_else(|| self.err("unterminated `for ((`"))?;
            self.blanks();
            if self.peek() == Some(';') {
                self.i += 1;
            }
            self.blanks_nl()?;
            let body = self.loop_body()?;
            return Ok(Kind::ArithFor { header, body });
        }
        let var = self.word()?;
        self.blanks();
        if self.peek() == Some(';') {
            self.i += 1;
        }
        self.blanks_nl()?;
        let mut items = None;
        if self.take_word("in") {
            let mut v = Vec::new();
            loop {
                self.blanks();
                match self.peek() {
                    Some(';') => {
                        self.i += 1;
                        break;
                    }
                    Some('\n') | None => break,
                    _ => v.push(self.word()?),
                }
            }
            items = Some(v);
        }
        self.blanks_nl()?;
        let body = self.loop_body()?;
        Ok(Kind::For { var, items, body })
    }

    fn loop_body(&mut self) -> R<Script> {
        if self.take_word("do") {
            let body = self.list(&End::Words(&["done"]))?;
            self.expect_word("done")?;
            return Ok(body);
        }
        if self.take_word("{") {
            let body = self.list(&End::Words(&["}"]))?;
            self.expect_word("}")?;
            return Ok(body);
        }
        Err(self.err("expected `do`"))
    }

    fn case_cmd(&mut self) -> R<Kind> {
        self.i += 4;
        self.blanks();
        let subject = self.word()?;
        self.expect_word("in")?;
        let mut arms = Vec::new();
        loop {
            self.blanks_nl()?;
            if self.take_word("esac") {
                return Ok(Kind::Case { subject, arms });
            }
            if self.peek() == Some('(') {
                self.i += 1;
            }
            let mut pats = Vec::new();
            loop {
                self.blanks();
                pats.push(self.word()?);
                self.blanks();
                match self.peek() {
                    Some('|') => self.i += 1,
                    Some(')') => {
                        self.i += 1;
                        break;
                    }
                    _ => return Err(self.err("expected `)` after a case pattern")),
                }
            }
            let body = self.list(&End::CaseArm)?;
            arms.push((pats, body));
            self.blanks();
            for op in [";;&", ";;", ";&"] {
                if self.starts(op) {
                    self.i += op.len();
                    break;
                }
            }
        }
    }

    fn cond_cmd(&mut self) -> R<Kind> {
        self.i += 2;
        let mut words = Vec::new();
        loop {
            self.blanks_nl()?;
            if self.take_word("]]") {
                return Ok(Kind::Cond(words));
            }
            match self.peek() {
                None => return Err(self.err("unterminated `[[`")),
                Some(c @ ('(' | ')' | '!')) => {
                    self.i += 1;
                    words.push(lit_word(&c.to_string()));
                }
                Some('&' | '|' | '<' | '>') if self.at(1) != Some('(') => {
                    let start = self.i;
                    self.i += 1;
                    if matches!(self.peek(), Some('&' | '|')) {
                        self.i += 1;
                    }
                    let t: String = self.s[start..self.i].iter().collect();
                    words.push(lit_word(&t));
                }
                _ => words.push(self.word()?),
            }
        }
    }

    /// Tries `((...))` (or `$((...))` after the `$`) at the cursor; `skip`
    /// is the number of `(` to consume. `None` (cursor restored) when the
    /// text does not close with `))`: it is then a subshell.
    fn arith(&mut self, skip: usize) -> R<Option<Part>> {
        let save = self.i;
        self.i += skip;
        let mut text = String::new();
        let mut subs = Vec::new();
        let mut level = 0usize;
        loop {
            let Some(c) = self.peek() else {
                self.i = save;
                return Ok(None);
            };
            match c {
                '(' => {
                    level += 1;
                    text.push(c);
                    self.i += 1;
                }
                ')' if level == 0 => {
                    if self.at(1) == Some(')') {
                        self.i += 2;
                        return Ok(Some(Part::Arith(text, subs)));
                    }
                    self.i = save;
                    return Ok(None);
                }
                ')' => {
                    level -= 1;
                    text.push(c);
                    self.i += 1;
                }
                '$' => {
                    let p = self.dollar(false)?;
                    collect_owned(p, &mut subs, &mut text);
                }
                '`' => {
                    self.i += 1;
                    subs.push(self.backtick(false)?);
                    text.push_str("`...`");
                }
                '\'' | '"' => {
                    let w = self.word_part_quote()?;
                    text.push_str(&w);
                }
                _ => {
                    text.push(c);
                    self.i += 1;
                }
            }
        }
    }

    /// A quote inside an arithmetic expression, as text.
    fn word_part_quote(&mut self) -> R<String> {
        let q = self.peek().unwrap_or('\'');
        let start = self.i;
        self.i += 1;
        while let Some(c) = self.peek() {
            self.i += 1;
            if c == '\\' && q == '"' {
                self.i += 1;
                continue;
            }
            if c == q {
                return Ok(self.s[start..self.i].iter().collect());
            }
        }
        Err(self.err("unterminated quote"))
    }

    fn at_redir(&self) -> bool {
        let mut k = 0;
        while self.at(k).is_some_and(|c| c.is_ascii_digit()) {
            k += 1;
        }
        if k == 0 && self.peek() == Some('{') {
            let mut j = 1;
            while self
                .at(j)
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                j += 1;
            }
            if j > 1 && self.at(j) == Some('}') && matches!(self.at(j + 1), Some('<' | '>')) {
                return true;
            }
        }
        match self.at(k) {
            Some('<' | '>') => self.at(k + 1) != Some('('),
            Some('&') => k == 0 && self.at(1) == Some('>'),
            _ => false,
        }
    }

    fn redir(&mut self) -> R<Redir> {
        let mut fd = None;
        let mut var = None;
        let start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i > start {
            let n: String = self.s[start..self.i].iter().collect();
            fd = Some(n.parse().map_err(|_| self.err("bad fd number"))?);
        } else if self.peek() == Some('{') {
            let close = (self.i..self.s.len())
                .find(|&k| self.s[k] == '}')
                .ok_or_else(|| self.err("bad `{fd}` redirection"))?;
            var = Some(self.s[self.i + 1..close].iter().collect());
            self.i = close + 1;
        }
        let ops: [(&str, Op); 12] = [
            ("&>>", Op::AppendErr),
            ("<<<", Op::HereStr),
            ("<<-", Op::Here),
            ("<<", Op::Here),
            ("<>", Op::ReadWrite),
            ("<&", Op::DupIn),
            ("<", Op::In),
            (">>", Op::Append),
            (">|", Op::Clobber),
            (">&", Op::DupOut),
            (">", Op::Out),
            ("&>", Op::OutErr),
        ];
        let (text, op) = ops
            .iter()
            .find(|(t, _)| self.starts(t))
            .copied()
            .ok_or_else(|| self.err("bad redirection"))?;
        self.i += text.len();
        self.blanks();
        if self
            .peek()
            .is_none_or(|c| is_meta(c) && c != '<' && c != '>')
        {
            return Err(self.err("redirection without a target"));
        }
        let target = self.word()?;
        let mut doc = None;
        if op == Op::Here {
            let quoted = target.raw.contains(['\'', '"', '\\']);
            let delim: String = unquote_raw(&target.raw);
            let d = Rc::new(RefCell::new(Doc {
                quoted,
                ..Doc::default()
            }));
            self.pending.push((delim, text == "<<-", Rc::clone(&d)));
            doc = Some(d);
        }
        Ok(Redir {
            fd,
            var,
            op,
            target,
            doc,
        })
    }

    fn simple(&mut self) -> R<Command> {
        let mut sc = Simple::default();
        let mut redirs = Vec::new();
        loop {
            self.blanks();
            if self.at_redir() {
                redirs.push(self.redir()?);
                continue;
            }
            match self.peek() {
                None | Some('\n' | ';' | '&' | '|' | ')') => break,
                Some('(') => {
                    if sc.words.len() == 1 && sc.assigns.is_empty() && redirs.is_empty() {
                        self.i += 1;
                        self.blanks();
                        if self.peek() != Some(')') {
                            return Err(self.err("unexpected `(`"));
                        }
                        self.i += 1;
                        self.blanks_nl()?;
                        let body = self.command()?;
                        let name = sc.words.remove(0);
                        return Ok(Command {
                            kind: Kind::Func {
                                name,
                                body: Box::new(body),
                            },
                            redirs: Vec::new(),
                        });
                    }
                    return Err(self.err("unexpected `(`"));
                }
                _ => {}
            }
            let w = self.word()?;
            // `NAME=(a b)`: an array value (also in `declare` arguments).
            let array_value =
                self.peek() == Some('(') && w.raw.ends_with('=') && split_assign(&w).is_some();
            if array_value {
                self.i += 1;
                let mut items = Vec::new();
                loop {
                    self.blanks_nl()?;
                    match self.peek() {
                        Some(')') => {
                            self.i += 1;
                            break;
                        }
                        None => return Err(self.err("unterminated array")),
                        _ => items.push(self.word()?),
                    }
                }
                let (name, _) = split_assign(&w).unwrap_or_default();
                if sc.words.is_empty() {
                    sc.assigns.push(Assign {
                        name,
                        raw: w.raw.clone(),
                        value: items,
                        array: true,
                    });
                } else {
                    sc.words.push(w);
                    sc.words.extend(items);
                }
                continue;
            }
            if sc.words.is_empty()
                && let Some((name, value)) = split_assign(&w)
            {
                sc.assigns.push(Assign {
                    name,
                    raw: w.raw.clone(),
                    value: vec![value],
                    array: false,
                });
                continue;
            }
            sc.words.push(w);
        }
        Ok(Command {
            kind: Kind::Simple(sc),
            redirs,
        })
    }

    /// One word at the cursor.
    fn word(&mut self) -> R<Word> {
        let start = self.i;
        let mut parts: Vec<Part> = Vec::new();
        let mut lit = String::new();
        // Unquoted `{`, `}`, `,` and `.` with placeholders, for brace
        // expansion.
        let mut probe = String::new();
        let flush = |lit: &mut String, parts: &mut Vec<Part>| {
            if !lit.is_empty() {
                parts.push(Part::Lit(std::mem::take(lit)));
            }
        };
        while let Some(c) = self.peek() {
            match c {
                c if is_meta(c) && !matches!(c, '<' | '>') => break,
                '<' | '>' => {
                    if self.at(1) != Some('(') {
                        break;
                    }
                    self.i += 2;
                    self.deeper()?;
                    let s = self.sub_list()?;
                    self.depth -= 1;
                    flush(&mut lit, &mut parts);
                    parts.push(Part::ProcSub(s));
                    probe.push('x');
                }
                '\\' => {
                    self.i += 1;
                    match self.peek() {
                        Some('\n') => self.i += 1,
                        Some(n) => {
                            lit.push(n);
                            self.i += 1;
                        }
                        None => lit.push('\\'),
                    }
                    probe.push('x');
                }
                '\'' => {
                    self.i += 1;
                    let mut t = String::new();
                    loop {
                        match self.peek() {
                            None => return Err(self.err("unterminated single quote")),
                            Some('\'') => {
                                self.i += 1;
                                break;
                            }
                            Some(ch) => {
                                t.push(ch);
                                self.i += 1;
                            }
                        }
                    }
                    flush(&mut lit, &mut parts);
                    parts.push(Part::Single(t));
                    probe.push('x');
                }
                '"' => {
                    self.i += 1;
                    let d = self.double()?;
                    flush(&mut lit, &mut parts);
                    parts.push(d);
                    probe.push('x');
                }
                '`' => {
                    self.i += 1;
                    let s = self.backtick(false)?;
                    flush(&mut lit, &mut parts);
                    parts.push(Part::Backtick(s));
                    probe.push('x');
                }
                '$' => {
                    let p = self.dollar(false)?;
                    match p {
                        Part::Lit(t) => lit.push_str(&t),
                        other => {
                            flush(&mut lit, &mut parts);
                            parts.push(other);
                        }
                    }
                    probe.push('x');
                }
                '*' | '?' => {
                    self.i += 1;
                    flush(&mut lit, &mut parts);
                    parts.push(Part::Glob(c));
                    probe.push('x');
                }
                '[' if self.closes_bracket() => {
                    self.i += 1;
                    flush(&mut lit, &mut parts);
                    parts.push(Part::Glob('['));
                    probe.push('x');
                }
                '~' if self.i == start => {
                    self.i += 1;
                    let mut user = String::new();
                    while let Some(ch) = self.peek() {
                        if is_meta(ch) || matches!(ch, '/' | '\'' | '"' | '\\' | '$' | '`' | ':') {
                            break;
                        }
                        user.push(ch);
                        self.i += 1;
                    }
                    parts.push(Part::Tilde(user));
                    probe.push('x');
                }
                _ => {
                    lit.push(c);
                    self.i += 1;
                    probe.push(if matches!(c, '{' | '}' | ',' | '.') {
                        c
                    } else {
                        'x'
                    });
                }
            }
        }
        flush(&mut lit, &mut parts);
        if self.i == start {
            return Err(self.err("expected a word"));
        }
        Ok(Word {
            parts,
            brace: brace_expands(&probe),
            raw: self.s[start..self.i].iter().collect(),
        })
    }

    /// True when an unquoted `]` follows in the same word (a bracket
    /// expression).
    fn closes_bracket(&self) -> bool {
        let mut k = self.i + 1;
        while let Some(&c) = self.s.get(k) {
            if is_meta(c) || matches!(c, '\'' | '"' | '\\' | '$' | '`') {
                return false;
            }
            if c == ']' {
                return true;
            }
            k += 1;
        }
        false
    }

    /// The rest of a double-quoted string, after `"`.
    fn double(&mut self) -> R<Part> {
        let mut parts = Vec::new();
        let mut lit = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated double quote"));
            };
            match c {
                '"' => {
                    self.i += 1;
                    break;
                }
                '\\' => {
                    self.i += 1;
                    match self.peek() {
                        Some('\n') => self.i += 1,
                        Some(n @ ('$' | '`' | '"' | '\\')) => {
                            lit.push(n);
                            self.i += 1;
                        }
                        _ => lit.push('\\'),
                    }
                }
                '$' => match self.dollar(true)? {
                    Part::Lit(t) => lit.push_str(&t),
                    p => {
                        if !lit.is_empty() {
                            parts.push(Part::Lit(std::mem::take(&mut lit)));
                        }
                        parts.push(p);
                    }
                },
                '`' => {
                    self.i += 1;
                    let s = self.backtick(true)?;
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit)));
                    }
                    parts.push(Part::Backtick(s));
                }
                _ => {
                    lit.push(c);
                    self.i += 1;
                }
            }
        }
        if !lit.is_empty() {
            parts.push(Part::Lit(lit));
        }
        Ok(Part::Double(parts))
    }

    /// The text of a backquoted substitution (after the opening
    /// backquote), parsed.
    fn backtick(&mut self, in_double: bool) -> R<Script> {
        let mut text = String::new();
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated backquote"));
            };
            self.i += 1;
            match c {
                '`' => break,
                '\\' => match self.peek() {
                    Some(n @ ('$' | '`' | '\\')) => {
                        text.push(n);
                        self.i += 1;
                    }
                    Some('"') if in_double => {
                        text.push('"');
                        self.i += 1;
                    }
                    _ => text.push('\\'),
                },
                _ => text.push(c),
            }
        }
        parse_at(&text, self.depth + 1)
    }

    /// A `$` expansion at the cursor. `Part::Lit("$")` for a `$` that
    /// starts nothing.
    fn dollar(&mut self, in_double: bool) -> R<Part> {
        self.i += 1;
        match self.peek() {
            Some('(') => {
                if self.at(1) == Some('(')
                    && let Some(a) = self.arith(2)?
                {
                    return Ok(a);
                }
                self.i += 1;
                self.deeper()?;
                let s = self.sub_list()?;
                self.depth -= 1;
                Ok(Part::CmdSub(s))
            }
            Some('{') => {
                self.i += 1;
                let (text, subs) = self.braced_param()?;
                Ok(Part::Param(format!("{{{text}}}"), subs))
            }
            Some('\'') if !in_double => {
                self.i += 1;
                let start = self.i;
                loop {
                    match self.peek() {
                        None => return Err(self.err("unterminated $'...'")),
                        Some('\'') => break,
                        Some('\\') => self.i += 2,
                        Some(_) => self.i += 1,
                    }
                }
                let end = self.i.min(self.s.len());
                let raw: String = self.s[start..end].iter().collect();
                self.i = end + 1;
                Ok(Part::AnsiC(raw))
            }
            Some('"') if !in_double => {
                self.i += 1;
                self.double()
            }
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {
                let mut name = String::new();
                while let Some(ch) = self.peek() {
                    if !(ch.is_ascii_alphanumeric() || ch == '_') {
                        break;
                    }
                    name.push(ch);
                    self.i += 1;
                }
                Ok(Part::Param(name, Vec::new()))
            }
            Some(c) if c.is_ascii_digit() || "@*#?-$!".contains(c) => {
                self.i += 1;
                Ok(Part::Param(c.to_string(), Vec::new()))
            }
            _ => Ok(Part::Lit("$".into())),
        }
    }

    /// The inside of `${...}` (after `${`), through the closing `}`.
    fn braced_param(&mut self) -> R<(String, Vec<Script>)> {
        let mut text = String::new();
        let mut subs = Vec::new();
        let mut level = 0usize;
        loop {
            let Some(c) = self.peek() else {
                return Err(self.err("unterminated ${"));
            };
            match c {
                '}' if level == 0 => {
                    self.i += 1;
                    return Ok((text, subs));
                }
                '}' => {
                    level -= 1;
                    text.push(c);
                    self.i += 1;
                }
                '{' => {
                    level += 1;
                    text.push(c);
                    self.i += 1;
                }
                '\\' => {
                    text.push(c);
                    self.i += 1;
                    if let Some(n) = self.peek() {
                        text.push(n);
                        self.i += 1;
                    }
                }
                '\'' => {
                    let q = self.word_part_quote()?;
                    text.push_str(&q);
                }
                '"' => {
                    self.i += 1;
                    let d = self.double()?;
                    text.push_str("\"...\"");
                    collect_owned(d, &mut subs, &mut String::new());
                }
                '$' => {
                    let p = self.dollar(false)?;
                    collect_owned(p, &mut subs, &mut text);
                }
                '`' => {
                    self.i += 1;
                    subs.push(self.backtick(false)?);
                    text.push_str("`...`");
                }
                _ => {
                    text.push(c);
                    self.i += 1;
                }
            }
        }
    }
}

/// Adds the scripts of part `p` to `subs` and a stand-in for it to `text`.
fn collect_owned(p: Part, subs: &mut Vec<Script>, text: &mut String) {
    match p {
        Part::Lit(t) => text.push_str(&t),
        Part::Param(t, s) => {
            text.push('$');
            text.push_str(&t);
            subs.extend(s);
        }
        Part::Arith(t, s) => {
            text.push_str("$((");
            text.push_str(&t);
            text.push_str("))");
            subs.extend(s);
        }
        Part::CmdSub(s) | Part::Backtick(s) | Part::ProcSub(s) => {
            text.push_str("$(...)");
            subs.push(s);
        }
        Part::Double(inner) => {
            for q in inner {
                collect_owned(q, subs, text);
            }
        }
        Part::AnsiC(t) => {
            text.push_str("$'");
            text.push_str(&t);
            text.push('\'');
        }
        Part::Single(t) => text.push_str(&t),
        Part::Glob(c) => text.push(c),
        Part::Tilde(u) => {
            text.push('~');
            text.push_str(&u);
        }
    }
}

/// A word of fixed text.
fn lit_word(t: &str) -> Word {
    Word {
        parts: vec![Part::Lit(t.to_owned())],
        brace: false,
        raw: t.to_owned(),
    }
}

/// The delimiter of a heredoc as bash compares it: quotes and backslashes
/// removed from the source text.
fn unquote_raw(raw: &str) -> String {
    let mut out = String::new();
    let mut chars = raw.chars();
    let mut quote: Option<char> = None;
    while let Some(c) = chars.next() {
        match (quote, c) {
            (None, '\'' | '"') => quote = Some(c),
            (Some(q), c) if c == q => quote = None,
            (None | Some('"'), '\\') => {
                if let Some(n) = chars.next() {
                    out.push(n);
                }
            }
            _ => out.push(c),
        }
    }
    out
}

/// True when the unquoted structure of a word (`{`, `}`, `,`, `.`, and `x`
/// for anything else) has a `{...}` holding a `,` or `..` at its level.
fn brace_expands(probe: &str) -> bool {
    let chars: Vec<char> = probe.chars().collect();
    let mut stack: Vec<bool> = Vec::new();
    for (k, &c) in chars.iter().enumerate() {
        match c {
            '{' => stack.push(false),
            ',' => {
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            '.' if chars.get(k + 1) == Some(&'.') => {
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            '}' if stack.pop() == Some(true) => return true,
            _ => {}
        }
    }
    false
}

/// `NAME=`, `NAME+=` or `NAME[...]=` at the start of a word (the name
/// unquoted): the name and the value word.
#[must_use]
pub fn split_assign(w: &Word) -> Option<(String, Word)> {
    let Some(Part::Lit(first)) = w.parts.first() else {
        return None;
    };
    let name_len = first
        .char_indices()
        .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '_'))
        .map_or(first.len(), |(k, _)| k);
    let name = &first[..name_len];
    if !is_name(name) {
        return None;
    }
    let rest = &first[name_len..];
    // The value text in the literal part `parts[at - 1]`, and the parts
    // after it.
    let (after, at) = if let Some(r) = rest.strip_prefix("+=") {
        (r.to_owned(), 1)
    } else if let Some(r) = rest.strip_prefix('=') {
        (r.to_owned(), 1)
    } else if rest.starts_with('[')
        || (rest.is_empty() && matches!(w.parts.get(1), Some(Part::Glob('['))))
    {
        // `NAME[sub]=`: the subscript closes with `]=` or `]+=` in a later
        // literal part (a `[` with a `]` in the same word is a glob part).
        if let Some(v) = after_subscript(rest) {
            (v, 1)
        } else {
            let mut found = None;
            for (k, p) in w.parts.iter().enumerate().skip(1) {
                match p {
                    Part::Lit(t) => {
                        if let Some(v) = after_subscript(t) {
                            found = Some((v, k + 1));
                            break;
                        }
                    }
                    Part::Glob(_) | Part::Param(..) | Part::Single(_) | Part::Double(_) => {}
                    _ => return None,
                }
            }
            found?
        }
    } else {
        return None;
    };
    let mut parts: Vec<Part> = Vec::new();
    if let Some(user) = after.strip_prefix('~') {
        let end = user.find(['/', ':']).unwrap_or(user.len());
        parts.push(Part::Tilde(user[..end].to_owned()));
        if end < user.len() {
            parts.push(Part::Lit(user[end..].to_owned()));
        }
    } else if !after.is_empty() {
        parts.push(Part::Lit(after));
    }
    parts.extend(w.parts[at..].iter().cloned());
    let raw = w.raw.split_once('=').map_or("", |(_, v)| v).to_owned();
    Some((
        name.to_owned(),
        Word {
            parts,
            brace: w.brace,
            raw,
        },
    ))
}

/// The text after `]=` or `]+=` in `t`.
fn after_subscript(t: &str) -> Option<String> {
    let k = t.find(']')?;
    let r = &t[k + 1..];
    r.strip_prefix("+=")
        .or_else(|| r.strip_prefix('='))
        .map(str::to_owned)
}

/// The parts of an unquoted heredoc body: parameters and substitutions
/// expand; `\` escapes only `$`, backquote, `\` and newline.
fn expand_doc(body: &str, depth: usize) -> R<Vec<Part>> {
    let mut p = Parser {
        s: body.chars().collect(),
        i: 0,
        pending: Vec::new(),
        depth,
    };
    let mut parts = Vec::new();
    let mut lit = String::new();
    while let Some(c) = p.peek() {
        match c {
            '\\' => {
                p.i += 1;
                match p.peek() {
                    Some('\n') => p.i += 1,
                    Some(n @ ('$' | '`' | '\\')) => {
                        lit.push(n);
                        p.i += 1;
                    }
                    _ => lit.push('\\'),
                }
            }
            '$' => match p.dollar(true)? {
                Part::Lit(t) => lit.push_str(&t),
                other => {
                    if !lit.is_empty() {
                        parts.push(Part::Lit(std::mem::take(&mut lit)));
                    }
                    parts.push(other);
                }
            },
            '`' => {
                p.i += 1;
                let s = p.backtick(false)?;
                if !lit.is_empty() {
                    parts.push(Part::Lit(std::mem::take(&mut lit)));
                }
                parts.push(Part::Backtick(s));
            }
            _ => {
                lit.push(c);
                p.i += 1;
            }
        }
    }
    if !lit.is_empty() {
        parts.push(Part::Lit(lit));
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The literal words of every simple command, in order (nested
    /// substitutions after the command that holds them).
    fn words(src: &str) -> Vec<Vec<Option<String>>> {
        let mut out = Vec::new();
        walk(&parse(src).unwrap(), &mut out);
        out
    }

    fn walk(s: &Script, out: &mut Vec<Vec<Option<String>>>) {
        for ao in &s.items {
            for p in std::iter::once(&ao.first).chain(ao.rest.iter().map(|(_, p)| p)) {
                for c in &p.cmds {
                    match &c.kind {
                        Kind::Simple(sc) => {
                            out.push(sc.words.iter().map(Word::literal).collect());
                            for w in &sc.words {
                                for sub in w.scripts() {
                                    walk(sub, out);
                                }
                            }
                        }
                        Kind::Subshell(b) | Kind::Group(b) => walk(b, out),
                        Kind::If { arms, other } => {
                            for (c, b) in arms {
                                walk(c, out);
                                walk(b, out);
                            }
                            if let Some(o) = other {
                                walk(o, out);
                            }
                        }
                        Kind::Case { arms, .. } => {
                            for (_, b) in arms {
                                walk(b, out);
                            }
                        }
                        Kind::Func { body, .. } => {
                            if let Kind::Group(b) = &body.kind {
                                walk(b, out);
                            }
                        }
                        Kind::Loop { cond, body } => {
                            walk(cond, out);
                            walk(body, out);
                        }
                        Kind::For { body, .. } => walk(body, out),
                        _ => {}
                    }
                }
            }
        }
    }

    fn lit(v: &[&str]) -> Vec<Option<String>> {
        v.iter().map(|s| Some((*s).to_owned())).collect()
    }

    #[test]
    fn lists_pipes_quotes_and_escapes() {
        assert_eq!(
            words("cd x && git commit -m 'a b' ; echo \"c d\" | tee f\ngit com\\\nmit"),
            vec![
                lit(&["cd", "x"]),
                lit(&["git", "commit", "-m", "a b"]),
                lit(&["echo", "c d"]),
                lit(&["tee", "f"]),
                lit(&["git", "commit"]),
            ]
        );
        assert_eq!(
            words("git commit --no-\"verify\" '-n' --no-ver\\ify -\"n\""),
            vec![lit(&[
                "git",
                "commit",
                "--no-verify",
                "-n",
                "--no-verify",
                "-n"
            ])]
        );
        assert!(words("").is_empty());
        assert!(words("# only a comment\n").is_empty());
        assert_eq!(words("echo a#b # c"), vec![lit(&["echo", "a#b"])]);
    }

    #[test]
    fn expansions_are_not_literal_g1() {
        for src in [
            "${x}t commit",
            "$G commit",
            "$(echo git) commit",
            "`echo git` commit",
            "$'\\x67it' commit",
            "g*t commit",
            "gi? commit",
            "g[i]t commit",
            "{git,} commit",
            "$((1)) x",
            "~user/bin/git commit",
        ] {
            let w = words(src);
            assert_eq!(w[0][0], None, "{src}");
        }
        // Quotes and escapes give literal words; a lone `[` is a word.
        assert_eq!(
            words("\"git\" \\c'o'mmit [ -f x ]")[0][0].as_deref(),
            Some("git")
        );
        assert_eq!(words("[ -f x ]"), vec![lit(&["[", "-f", "x", "]"])]);
        assert_eq!(
            words("find . -exec rm {} +"),
            vec![lit(&["find", ".", "-exec", "rm", "{}", "+"])]
        );
    }

    /// `$'...'` ends where bash ends it: a backslash escapes the next
    /// character, so `\c\\` stays inside and the next quote closes.
    #[test]
    fn ansi_c_ends_as_bash_ends_it() {
        let w = words(r"echo $'\c\\' ; git commit -n");
        assert_eq!(w.len(), 2);
        assert_eq!(w[0][1], None);
        assert_eq!(w[1], lit(&["git", "commit", "-n"]));
    }

    /// Substitutions are parsed in place: a heredoc or a quote inside
    /// `$(...)` does not end it early, and the commands inside are seen.
    #[test]
    fn substitutions_are_parsed_in_place() {
        let src = "gh pr create --body \"$(cat <<'EOF'\n## Summary\n- don't (break\nEOF\n)\" && git status";
        let w = words(src);
        assert_eq!(w[0][0].as_deref(), Some("gh"));
        assert_eq!(w[0][4].as_deref(), Some("## Summary\n- don't (break"));
        assert!(w.contains(&lit(&["cat"])));
        assert!(w.contains(&lit(&["git", "status"])));
        let w = words("echo $(git commit -n) `git push -n` <(git am -n) \"${x:-$(git status)}\"");
        for want in [
            lit(&["git", "commit", "-n"]),
            lit(&["git", "push", "-n"]),
            lit(&["git", "am", "-n"]),
            lit(&["git", "status"]),
        ] {
            assert!(w.contains(&want), "{want:?} in {w:?}");
        }
    }

    /// The `"$(cat <<'EOF' ... EOF)"` message idiom is literal inside
    /// double quotes only.
    #[test]
    fn the_heredoc_message_idiom_is_literal_in_double_quotes() {
        let w = words("git commit -m \"$(cat <<'EOF'\nSubject\n\nBody\nEOF\n)\"");
        assert_eq!(w[0][3].as_deref(), Some("Subject\n\nBody"));
        let w = words("git commit -m $(cat <<'EOF'\nx --no-verify\nEOF\n)");
        assert_eq!(w[0][3], None);
        let w = words("git commit -m \"$(cat <<EOF\n$HOME\nEOF\n)\"");
        assert_eq!(w[0][3], None);
        let w = words("git commit -m \"$(cat <<EOF\nplain\nEOF\n)\"");
        assert_eq!(w[0][3].as_deref(), Some("plain"));
    }

    #[test]
    fn heredocs_assignments_and_redirections() {
        let s =
            parse("A=1 B=\"x y\" git log >out 2>&1 <<-'E'\n\tbody $x\n\tE\necho {fd}>f").unwrap();
        let Kind::Simple(sc) = &s.items[0].first.cmds[0].kind else {
            panic!()
        };
        assert_eq!(sc.assigns[0].name, "A");
        assert_eq!(sc.assigns[1].value[0].literal().as_deref(), Some("x y"));
        let r = &s.items[0].first.cmds[0].redirs;
        assert_eq!(r.len(), 3);
        assert!(r[0].writes_file() && !r[1].writes_file());
        let doc = r[2].doc.as_ref().unwrap().borrow();
        assert!(doc.quoted);
        assert_eq!(doc.body, "body $x\n");
        let r = &s.items[1].first.cmds[0].redirs;
        assert_eq!(r[0].var.as_deref(), Some("fd"));
        // Unquoted heredoc bodies expand: their substitutions are commands.
        let s = parse("cat <<EOF\n$(git commit -n)\nEOF").unwrap();
        let doc = s.items[0].first.cmds[0].redirs[0].doc.clone().unwrap();
        assert!(matches!(doc.borrow().parts[0], Part::CmdSub(_)));
        assert!(split_assign(&parse_word("X[1]=2")).is_some());
        assert!(split_assign(&parse_word("X+=2")).is_some());
        assert!(split_assign(&parse_word("\"X\"=2")).is_none());
        assert!(split_assign(&parse_word("--a=b")).is_none());
    }

    fn parse_word(src: &str) -> Word {
        let mut p = Parser {
            s: src.chars().collect(),
            i: 0,
            pending: Vec::new(),
            depth: 0,
        };
        p.word().unwrap()
    }

    #[test]
    fn compound_commands() {
        let w = words(
            "for f in a b; do git -C \"$f\" status; done\nif x; then y; elif z; then w; else v; fi\nwhile read l; do echo; done < f\ncase $x in a|b) one;; *) two;; esac\nf() { g; }\n[[ $x == y && -n $(h) ]]\n(( i++ ))\n{ k; } > o",
        );
        assert!(w.contains(&vec![
            Some("git".into()),
            Some("-C".into()),
            None,
            Some("status".into())
        ]));
        for want in ["x", "y", "z", "w", "v", "read", "echo", "k"] {
            assert!(
                w.iter().any(|c| c.first() == Some(&Some(want.to_owned()))),
                "{want}"
            );
        }
    }

    #[test]
    fn errors_fail_closed() {
        for src in [
            "echo 'unterminated",
            "echo \"unterminated",
            "echo $(unterminated",
            "coproc x",
            "echo a(b)",
            "if x; then y",
            "cat >",
            "echo `x",
            "fi",
        ] {
            assert!(parse(src).is_err(), "{src}");
        }
    }

    #[test]
    fn brace_expansion_is_detected() {
        for (src, want) in [
            ("{a,b}", true),
            ("x{1..3}", true),
            ("{}", false),
            ("{a}", false),
            ("'{a,b}'", false),
            ("\\{a,b}", false),
            ("a,b", false),
        ] {
            assert_eq!(parse_word(src).brace, want, "{src}");
        }
    }
}
