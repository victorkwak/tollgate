//! A small POSIX-shell lexer for the guard's text rules (R25, R26, R28).
//!
//! It splits a Bash command into simple commands with their words (quotes
//! removed), leading assignments and redirections. Command substitutions
//! (`$(...)`, backticks), process substitutions (`<(...)`, `>(...)`) and
//! subshells are parsed as commands too. Heredoc bodies are data: they are
//! kept on their redirection, not parsed as commands, except the `$(...)`
//! and backtick substitutions of a body whose delimiter is not quoted,
//! which bash runs (a heredoc, here-string or pipe into a shell is denied
//! in commands that name git, item 31). Words of a top-level command keep
//! their place in the source, so a rule can tell a literal message from
//! text bash reads as code (item 42). Best effort: the guard is a backstop
//! behind the git hooks, so a construct this lexer does not model errs
//! toward more matches, not fewer.

/// One redirection of a simple command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Redirect {
    /// Operator: `>`, `>>`, `>|`, `&>`, `&>>`, `<>`, `<`, `<<` (also for
    /// `<<-`), `<<<`, `>&`, `<&`.
    pub op: String,
    /// Target word (file, fd, or heredoc delimiter).
    pub target: String,
    /// The command gets the text as written: for a heredoc, a quoted
    /// delimiter or a body without `$`, backticks and backslashes; for any
    /// other target, a word without `$` and backticks.
    pub literal: bool,
    /// A heredoc's body as the command reads it (`<<-` without the
    /// leading tabs); `None` until the line after the operator is read.
    pub body: Option<String>,
    /// Where the body is in the source this command came from (char
    /// indices, delimiter line excluded).
    pub body_span: Option<(usize, usize)>,
}

impl Redirect {
    /// True when the redirection writes a file.
    #[must_use]
    pub fn writes_file(&self) -> bool {
        match self.op.as_str() {
            ">" | ">>" | ">|" | "&>" | "&>>" | "<>" => true,
            // `>&file` (not an fd number or `-`) writes the file in bash.
            ">&" => {
                !self.target.is_empty()
                    && !self.target.bytes().all(|b| b.is_ascii_digit())
                    && self.target != "-"
            }
            _ => false,
        }
    }
}

/// A simple command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SimpleCommand {
    /// `NAME=value` words before the command name.
    pub assignments: Vec<String>,
    /// Command name and arguments, quotes removed.
    pub words: Vec<String>,
    /// Redirections.
    pub redirects: Vec<Redirect>,
    /// Its stdin is a pipe (after `|` or `|&`, or in a piped subshell).
    pub piped: bool,
    /// Where each word is in the source (char indices, parallel to
    /// `words`). Indices are into the text given to [`parse`] only when
    /// `top` is set; a nested command's are into its substitution.
    pub spans: Vec<(usize, usize)>,
    /// Parsed from the text given to [`parse`], not from a substitution,
    /// a subshell or a heredoc body.
    pub top: bool,
}

/// A heredoc whose body starts after the next newline.
struct PendingDoc {
    delim: String,
    strip_tabs: bool,
    quoted: bool,
    /// Index in `out` of its command and of the redirection there; `None`
    /// while the command is still being read.
    at: Option<usize>,
    redirect: usize,
}

struct Lexer<'a> {
    chars: Vec<char>,
    pos: usize,
    out: &'a mut Vec<SimpleCommand>,
    depth: usize,
    /// Set when a word uses ANSI-C quoting.
    ansi_c: &'a mut bool,
}

const MAX_DEPTH: usize = 16;

/// Parses `src` into simple commands, nested substitutions included.
#[must_use]
pub fn parse(src: &str) -> Vec<SimpleCommand> {
    parse_flagged(src).0
}

/// [`parse`], and whether a word uses ANSI-C quoting where bash reads it so:
/// `$'` in single or double quotes or in a heredoc body is data.
#[must_use]
pub fn parse_flagged(src: &str) -> (Vec<SimpleCommand>, bool) {
    let mut out = Vec::new();
    let mut ansi_c = false;
    parse_into(src, &mut out, 0, &mut ansi_c);
    (out, ansi_c)
}

fn parse_into(src: &str, out: &mut Vec<SimpleCommand>, depth: usize, ansi_c: &mut bool) {
    if depth > MAX_DEPTH {
        return;
    }
    let mut lx = Lexer {
        chars: src.chars().collect(),
        pos: 0,
        out,
        depth,
        ansi_c,
    };
    lx.run();
}

impl Lexer<'_> {
    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<char> {
        self.chars.get(self.pos + n).copied()
    }

    fn nested(&mut self, src: &str) {
        let mut inner = Vec::new();
        parse_into(src, &mut inner, self.depth + 1, self.ansi_c);
        self.out.extend(inner);
    }

    /// Reads up to the `)` that closes a `(` just consumed; returns the
    /// text between.
    fn read_balanced_paren(&mut self) -> String {
        let start = self.pos;
        let mut level = 1usize;
        while let Some(c) = self.peek() {
            match c {
                '\\' => self.pos += 2,
                '\'' => {
                    self.pos += 1;
                    while self.peek().is_some_and(|c| c != '\'') {
                        self.pos += 1;
                    }
                    self.pos += 1;
                }
                '"' => {
                    self.pos += 1;
                    while let Some(c) = self.peek() {
                        if c == '\\' {
                            self.pos += 2;
                            continue;
                        }
                        self.pos += 1;
                        if c == '"' {
                            break;
                        }
                    }
                }
                '(' => {
                    level += 1;
                    self.pos += 1;
                }
                ')' => {
                    level -= 1;
                    if level == 0 {
                        let text: String = self.chars[start..self.pos].iter().collect();
                        self.pos += 1;
                        return text;
                    }
                    self.pos += 1;
                }
                _ => self.pos += 1,
            }
        }
        self.pos = self.pos.min(self.chars.len());
        self.chars[start..].iter().collect()
    }

    /// Reads up to the closing backtick; returns the text between.
    fn read_backticks(&mut self) -> String {
        let mut text = String::new();
        while let Some(c) = self.peek() {
            self.pos += 1;
            match c {
                '\\' => {
                    if let Some(n) = self.peek() {
                        text.push(n);
                        self.pos += 1;
                    }
                }
                '`' => break,
                _ => text.push(c),
            }
        }
        text
    }

    /// Reads one word (quotes removed); `None` at an operator or the end.
    fn read_word(&mut self) -> Option<String> {
        let mut w = String::new();
        let mut any = false;
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' | '\n' | ';' | '&' | '|' | '(' | ')' => break,
                '<' | '>' => {
                    // `<(` and `>(` inside a word start a process
                    // substitution; otherwise a redirection ends the word.
                    if self.peek_at(1) == Some('(') {
                        self.pos += 2;
                        let inner = self.read_balanced_paren();
                        self.nested(&inner);
                        any = true;
                        continue;
                    }
                    break;
                }
                '\\' => {
                    self.pos += 1;
                    match self.peek() {
                        Some('\n') => self.pos += 1,
                        Some(n) => {
                            w.push(n);
                            self.pos += 1;
                        }
                        None => {}
                    }
                    any = true;
                }
                '\'' => {
                    self.pos += 1;
                    while let Some(c) = self.peek() {
                        self.pos += 1;
                        if c == '\'' {
                            break;
                        }
                        w.push(c);
                    }
                    any = true;
                }
                '"' => {
                    self.pos += 1;
                    while let Some(c) = self.peek() {
                        self.pos += 1;
                        match c {
                            '"' => break,
                            '\\' => match self.peek() {
                                Some(n @ ('"' | '\\' | '$' | '`')) => {
                                    w.push(n);
                                    self.pos += 1;
                                }
                                Some('\n') => self.pos += 1,
                                _ => w.push('\\'),
                            },
                            '$' if self.peek() == Some('(') => {
                                self.pos += 1;
                                let inner = self.read_balanced_paren();
                                self.nested(&inner);
                                w.push_str("$(");
                                w.push_str(&inner);
                                w.push(')');
                            }
                            '`' => {
                                let inner = self.read_backticks();
                                self.nested(&inner);
                                w.push_str(&inner);
                            }
                            _ => w.push(c),
                        }
                    }
                    any = true;
                }
                '`' => {
                    self.pos += 1;
                    let inner = self.read_backticks();
                    self.nested(&inner);
                    w.push_str(&inner);
                    any = true;
                }
                '$' if self.peek_at(1) == Some('(') => {
                    self.pos += 2;
                    let inner = self.read_balanced_paren();
                    self.nested(&inner);
                    w.push_str("$(");
                    w.push_str(&inner);
                    w.push(')');
                    any = true;
                }
                '$' if self.peek_at(1) == Some('\'') => {
                    self.pos += 2;
                    *self.ansi_c = true;
                    self.read_ansi_c(&mut w);
                    any = true;
                }
                // `$"..."` (a locale-translated string) is a double-quoted
                // string: the next pass reads it.
                '$' if self.peek_at(1) == Some('"') => self.pos += 1,
                _ => {
                    w.push(c);
                    self.pos += 1;
                    any = true;
                }
            }
        }
        any.then_some(w)
    }

    /// Reads the rest of an ANSI-C quoted string (`$'...'`, after the
    /// opening quote) into `w`. As bash does, the end is found first (a
    /// backslash escapes the next character, the first other `'` ends the
    /// string) and then the text is decoded ([`decode_ansi_c`]), so no
    /// escape can move the end.
    fn read_ansi_c(&mut self, w: &mut String) {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == '\'' {
                break;
            }
            self.pos += if c == '\\' { 2 } else { 1 };
        }
        let end = self.pos.min(self.chars.len());
        decode_ansi_c(&self.chars[start..end], w);
        self.pos = (end + 1).min(self.chars.len());
    }

    fn skip_blanks(&mut self) {
        while self.peek().is_some_and(|c| c == ' ' || c == '\t') {
            self.pos += 1;
        }
    }

    /// Reads a redirection operator at the current position.
    fn read_redirect_op(&mut self) -> String {
        let rest: String = self.chars[self.pos..].iter().take(3).collect();
        for op in [
            "&>>", "<<<", "<<-", ">>", ">|", ">&", "<&", "<>", "&>", "<<", ">", "<",
        ] {
            if rest.starts_with(op) {
                self.pos += op.chars().count();
                return op.into();
            }
        }
        self.pos += 1;
        rest.chars().next().map(String::from).unwrap_or_default()
    }

    /// Reads the heredoc bodies that start after a newline onto their
    /// redirections. A line equal to the delimiter ends a body (after
    /// leading tabs for `<<-` only, as bash does), and so does the end of
    /// the input. An unquoted body's substitutions are commands.
    fn read_heredocs(&mut self, docs: &mut Vec<PendingDoc>) {
        for d in std::mem::take(docs) {
            let start = self.pos;
            let mut end = self.pos;
            let mut body = String::new();
            while self.peek().is_some() {
                let line_start = self.pos;
                while self.peek().is_some_and(|c| c != '\n') {
                    self.pos += 1;
                }
                let line: String = self.chars[line_start..self.pos].iter().collect();
                if self.peek().is_some() {
                    self.pos += 1;
                }
                let line = if d.strip_tabs {
                    line.trim_start_matches('\t')
                } else {
                    line.as_str()
                };
                if line == d.delim {
                    break;
                }
                body.push_str(line);
                body.push('\n');
                end = self.pos;
            }
            let literal = d.quoted || !body.contains(['$', '`', '\\']);
            if !d.quoted {
                self.substitutions(&body);
            }
            if let Some(r) =
                d.at.and_then(|at| self.out.get_mut(at))
                    .and_then(|cmd| cmd.redirects.get_mut(d.redirect))
            {
                r.literal = literal;
                r.body = Some(body);
                r.body_span = Some((start, end));
            }
        }
    }

    /// Parses the `$(...)` and backtick substitutions of an unquoted
    /// heredoc body as commands; `\` escapes the next character there.
    fn substitutions(&mut self, body: &str) {
        let mut inner = Vec::new();
        let mut lx = Lexer {
            chars: body.chars().collect(),
            pos: 0,
            out: &mut inner,
            depth: self.depth,
            ansi_c: self.ansi_c,
        };
        while let Some(c) = lx.peek() {
            match c {
                '\\' => lx.pos += 2,
                '$' if lx.peek_at(1) == Some('(') => {
                    lx.pos += 2;
                    let text = lx.read_balanced_paren();
                    lx.nested(&text);
                }
                '`' => {
                    lx.pos += 1;
                    let text = lx.read_backticks();
                    lx.nested(&text);
                }
                _ => lx.pos += 1,
            }
        }
        self.out.extend(inner);
    }

    /// Ends the current command: it goes to `out`, and its heredocs learn
    /// where it is.
    fn flush(&mut self, cur: &mut SimpleCommand, docs: &mut [PendingDoc]) {
        if cur.words.is_empty() && cur.assignments.is_empty() && cur.redirects.is_empty() {
            return;
        }
        cur.top = self.depth == 0;
        for d in docs.iter_mut().filter(|d| d.at.is_none()) {
            d.at = Some(self.out.len());
        }
        self.out.push(std::mem::take(cur));
    }

    fn run(&mut self) {
        let mut cur = SimpleCommand::default();
        let mut heredocs: Vec<PendingDoc> = Vec::new();
        while let Some(c) = self.peek() {
            match c {
                ' ' | '\t' => self.pos += 1,
                '\n' => {
                    self.pos += 1;
                    self.flush(&mut cur, &mut heredocs);
                    self.read_heredocs(&mut heredocs);
                }
                ';' | ')' => {
                    self.pos += 1;
                    self.flush(&mut cur, &mut heredocs);
                }
                '|' => {
                    self.pos += 1;
                    self.flush(&mut cur, &mut heredocs);
                    match self.peek() {
                        // `||`: the next command runs after this one, not
                        // on its output.
                        Some('|') => {
                            self.pos += 1;
                            cur.piped = false;
                        }
                        // `|&` pipes stderr too.
                        Some('&') => {
                            self.pos += 1;
                            cur.piped = true;
                        }
                        _ => cur.piped = true,
                    }
                }
                '&' if self.peek_at(1) == Some('>') => {
                    let op = self.read_redirect_op();
                    self.skip_blanks();
                    let start = self.pos;
                    let target = self.read_word().unwrap_or_default();
                    let literal = !self.chars[start..self.pos]
                        .iter()
                        .any(|c| matches!(c, '$' | '`'));
                    cur.redirects.push(Redirect {
                        op,
                        target,
                        literal,
                        ..Redirect::default()
                    });
                }
                '&' => {
                    self.pos += 1;
                    self.flush(&mut cur, &mut heredocs);
                }
                '(' => {
                    self.pos += 1;
                    let piped = cur.piped;
                    self.flush(&mut cur, &mut heredocs);
                    cur.piped = false;
                    let inner = self.read_balanced_paren();
                    let first = self.out.len();
                    self.nested(&inner);
                    // Every command of a piped subshell may read the pipe.
                    if piped {
                        for c in &mut self.out[first..] {
                            c.piped = true;
                        }
                    }
                }
                '#' => {
                    while self.peek().is_some_and(|c| c != '\n') {
                        self.pos += 1;
                    }
                }
                '<' | '>' if self.peek_at(1) != Some('(') => {
                    let mut op = self.read_redirect_op();
                    self.skip_blanks();
                    let start = self.pos;
                    let target = self.read_word().unwrap_or_default();
                    let raw: String = self.chars[start..self.pos].iter().collect();
                    let strip_tabs = op == "<<-";
                    if strip_tabs {
                        op = "<<".into();
                    }
                    let literal = !raw.contains(['$', '`']);
                    if op == "<<" {
                        heredocs.push(PendingDoc {
                            delim: target.clone(),
                            strip_tabs,
                            quoted: raw.contains(['\'', '"', '\\']),
                            at: None,
                            redirect: cur.redirects.len(),
                        });
                    }
                    cur.redirects.push(Redirect {
                        op,
                        target,
                        literal,
                        ..Redirect::default()
                    });
                }
                _ => {
                    let before = self.pos;
                    let Some(w) = self.read_word() else {
                        if self.pos == before {
                            self.pos += 1;
                        }
                        continue;
                    };
                    // `2>file`: an fd number glued to a redirection.
                    if matches!(self.peek(), Some('<' | '>'))
                        && self.peek_at(1) != Some('(')
                        && !w.is_empty()
                        && w.bytes().all(|b| b.is_ascii_digit())
                    {
                        continue;
                    }
                    if cur.words.is_empty() && is_assignment(&w) {
                        cur.assignments.push(w);
                    } else if cur.words.is_empty() && matches!(w.as_str(), "{" | "}") {
                        // Group braces are not command words.
                    } else {
                        cur.words.push(w);
                        cur.spans.push((before, self.pos));
                    }
                }
            }
        }
        self.flush(&mut cur, &mut heredocs);
    }
}

/// bash's `\cx`: toupper(x) & 0x1f, and 0x7f for `?`.
fn control(x: char) -> char {
    if x == '?' {
        return '\x7f';
    }
    let v = u32::from(x.to_ascii_uppercase()) & 0x1f;
    char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER)
}

/// Decodes the text of an ANSI-C quoted string (`$'...'` without its
/// quotes) into `w` as bash 5 does: `\a \b \e \E \f \n \r \t \v \\ \' \"
/// \?`, octal `\nnn` (1-3 digits) and hex `\xHH` (1-2 digits) bytes,
/// `\uHHHH` and `\UHHHHHHHH` code points, and `\cx` control characters
/// ([`control`]; in `\c\\` the pair of backslashes is the `x`, and a
/// `\c` at the end stays as text). An unknown escape keeps its backslash.
/// A NUL ends the string (bash builds a C string); the rest is dropped. A
/// byte above 0x7f becomes the code point of the same value: only ASCII
/// matters to the rules.
fn decode_ansi_c(text: &[char], w: &mut String) {
    let code = |v: u32| char::from_u32(v).unwrap_or(char::REPLACEMENT_CHARACTER);
    // Up to `max` digits of `radix` at `text[*i..]`; `None` when none.
    let digits = |i: &mut usize, radix: u32, max: usize| -> Option<u32> {
        let mut value: Option<u32> = None;
        for _ in 0..max {
            let Some(d) = text.get(*i).and_then(|c| c.to_digit(radix)) else {
                break;
            };
            value = Some(value.unwrap_or(0).saturating_mul(radix).saturating_add(d));
            *i += 1;
        }
        value
    };
    let mut i = 0;
    while let Some(&c) = text.get(i) {
        i += 1;
        let decoded = if c == '\\' {
            let Some(&e) = text.get(i) else {
                w.push('\\');
                return;
            };
            i += 1;
            let known = match e {
                'a' => Some('\x07'),
                'b' => Some('\x08'),
                'e' | 'E' => Some('\x1b'),
                'f' => Some('\x0c'),
                'n' => Some('\n'),
                'r' => Some('\r'),
                't' => Some('\t'),
                'v' => Some('\x0b'),
                '\\' | '\'' | '"' | '?' => Some(e),
                '0'..='7' => {
                    i -= 1;
                    digits(&mut i, 8, 3).map(|v| code(v & 0xff))
                }
                'x' => digits(&mut i, 16, 2).map(code),
                'u' => digits(&mut i, 16, 4).map(code),
                'U' => digits(&mut i, 16, 8).map(code),
                'c' => text.get(i).copied().map(|x| {
                    i += 1;
                    if x == '\\' && text.get(i) == Some(&'\\') {
                        i += 1;
                    }
                    control(x)
                }),
                _ => None,
            };
            known.unwrap_or_else(|| {
                // Unknown, without digits, or `\c` at the end: the text
                // stays.
                w.push('\\');
                e
            })
        } else {
            c
        };
        if decoded == '\0' {
            return;
        }
        w.push(decoded);
    }
}

/// `NAME=value` (or bash's `NAME+=value`) with a valid shell name.
#[must_use]
pub fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let name = name.strip_suffix('+').unwrap_or(name);
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(src: &str) -> Vec<Vec<String>> {
        parse(src).into_iter().map(|c| c.words).collect()
    }

    #[test]
    fn splits_lists_pipes_and_quotes() {
        assert_eq!(
            words("cd x && git commit -m 'a b' ; echo \"c d\" | tee f"),
            vec![
                vec!["cd", "x"],
                vec!["git", "commit", "-m", "a b"],
                vec!["echo", "c d"],
                vec!["tee", "f"],
            ]
        );
    }

    #[test]
    fn substitutions_and_subshells_are_commands() {
        let w = words("echo $(git commit -n) `git push -n` (git am -n) <(git status)");
        assert!(w.contains(&vec!["git".into(), "commit".into(), "-n".into()]));
        assert!(w.contains(&vec!["git".into(), "push".into(), "-n".into()]));
        assert!(w.contains(&vec!["git".into(), "am".into(), "-n".into()]));
        assert!(w.contains(&vec!["git".into(), "status".into()]));
        let w = words("echo \"$(git commit -n)\"");
        assert!(w.contains(&vec!["git".into(), "commit".into(), "-n".into()]));
    }

    #[test]
    fn redirections_assignments_and_heredocs() {
        let cmds = parse(
            "A=1 B=2 git log >out.txt 2>&1\ncat <<EOF > f\ngit commit -n\nEOF\necho done 2> e &> both",
        );
        assert_eq!(cmds[0].assignments, vec!["A=1", "B=2"]);
        assert_eq!(cmds[0].words, vec!["git", "log"]);
        assert_eq!(
            cmds[0].redirects,
            vec![
                Redirect {
                    op: ">".into(),
                    target: "out.txt".into(),
                    literal: true,
                    ..Redirect::default()
                },
                Redirect {
                    op: ">&".into(),
                    target: "1".into(),
                    literal: true,
                    ..Redirect::default()
                }
            ]
        );
        assert!(cmds[0].redirects[0].writes_file());
        assert!(!cmds[0].redirects[1].writes_file());
        assert_eq!(cmds[1].words, vec!["cat"]);
        // The heredoc body is not a command.
        assert_eq!(cmds[2].words, vec!["echo", "done"]);
        assert_eq!(cmds[2].redirects.len(), 2);
        assert!(cmds[2].redirects.iter().all(Redirect::writes_file));
    }

    #[test]
    fn escapes_comments_and_unterminated_input() {
        assert_eq!(
            words("git com\\\nmit # a comment"),
            vec![vec!["git", "commit"]]
        );
        assert_eq!(
            words("echo 'unterminated"),
            vec![vec!["echo", "unterminated"]]
        );
        assert_eq!(words("echo $'a\\'b'"), vec![vec!["echo", "a'b"]]);
        assert!(words("").is_empty());
        assert!(is_assignment("X_1=2") && !is_assignment("1X=2") && !is_assignment("--a=b"));
        assert!(is_assignment("P+=x") && !is_assignment("+=x"));
    }

    /// ANSI-C quoting (`$'...'`) decodes as bash does, so a word spelled
    /// with escapes is the word the command gets (S1, S2).
    #[test]
    fn ansi_c_quotes_decode_as_bash_does() {
        for (src, want) in [
            (r"$'\x2d-no-verify'", "--no-verify"),
            (r"$'\055-no-verify'", "--no-verify"),
            (r"$'\x2dn'", "-n"),
            (r"$'-\U0000002dno-v'", "--no-v"),
            (r"$'\x47IT_CONFIG_COUNT=0'", "GIT_CONFIG_COUNT=0"),
            (r#"$'a\tb\nc\\d\'e\"f\?'"#, "a\tb\nc\\d'e\"f?"),
            (r"$'\a\b\e\E\f\r\v'", "\x07\x08\x1b\x1b\x0c\r\x0b"),
            (r"$'\cA\c['", "\x01\x1b"),
            // Unknown escapes and escapes without digits keep the
            // backslash.
            (r"$'\z\x\u'", r"\z\x\u"),
            // Octal takes at most three digits, hex at most two.
            (r"$'\1011\x414'", "A1A4"),
            // A NUL ends the string; the rest of the quote is dropped.
            (r"$'ab\x00cd'x", "abx"),
            // Glued to other quoting.
            (r"e$'\x6e'v", "env"),
            // `$"..."` is a double-quoted string.
            (r#"$"--no-verify""#, "--no-verify"),
        ] {
            assert_eq!(
                words(&format!("git {src}")),
                vec![vec!["git", want]],
                "{src}"
            );
        }
    }

    /// `\c` reads as bash 5 reads it: bash finds the end of `$'...'`
    /// first (a backslash escapes the next character), so `\c\\` is one
    /// control character and the quote after it closes the string; `\cx`
    /// is toupper(x) & 0x1f, `\c?` is 0x7f, and a `\c` at the end stays.
    #[test]
    fn ansi_c_control_escapes_match_bash() {
        assert_eq!(
            words(r"echo $'\c\\' ; echo next"),
            vec![vec!["echo", "\x1c"], vec!["echo", "next"]]
        );
        for (src, want) in [
            (r"$'\c\\x'", "\x1cx"),
            (r"$'\c\x'", "\x1cx"),
            (r"$'\c\'a'", "\x1c'a"),
            (r"$'\c\\\\'", "\x1c\\"),
            (r"$'\c'", r"\c"),
            (r"$'\ca\cA\c?\c[\c-'", "\x01\x01\x7f\x1b\r"),
            (r"$'a\cb'", "a\x02"),
        ] {
            assert_eq!(
                words(&format!("git {src}")),
                vec![vec!["git", want]],
                "{src}"
            );
        }
    }

    /// A heredoc keeps its body, whether bash expands it, and where it is;
    /// `<<` ends only at the delimiter itself, `<<-` also after tabs. An
    /// unquoted body's substitutions are commands; a quoted body's are not.
    #[test]
    fn heredoc_bodies_and_word_spans() {
        let src = "cat <<'A' | x <<-B\n$(no)\nA\n\tb\n\tB\nc \"d e\"";
        let cmds = parse(src);
        assert_eq!(cmds[0].redirects[0].body.as_deref(), Some("$(no)\n"));
        assert!(cmds[0].redirects[0].literal);
        let (a, b) = cmds[0].redirects[0].body_span.unwrap();
        assert_eq!(
            src.chars().skip(a).take(b - a).collect::<String>(),
            "$(no)\n"
        );
        assert_eq!(cmds[1].redirects[0].body.as_deref(), Some("b\n"));
        assert_eq!(cmds[2].words, vec!["c", "d e"]);
        assert!(cmds.iter().all(|c| c.top));
        let (a, b) = cmds[2].spans[1];
        assert_eq!(&src[a..b], "\"d e\"");
        // `<<` does not end at a tab-indented delimiter.
        let cmds = parse("cat <<A\n\tA\n$(y)\nA\nz");
        assert_eq!(cmds[0].redirects[0].body.as_deref(), Some("\tA\n$(y)\n"));
        assert!(!cmds[0].redirects[0].literal);
        let w: Vec<_> = cmds.iter().map(|c| (c.words.clone(), c.top)).collect();
        assert_eq!(
            w,
            vec![
                (vec!["cat".to_owned()], true),
                (vec!["y".to_owned()], false),
                (vec!["z".to_owned()], true)
            ]
        );
        // An escaped `$` is text.
        assert_eq!(words("cat <<A\n\\$(y)\nA").len(), 1);
    }

    /// A command after `|` or `|&` reads a pipe; after `||` it does not.
    /// Every command of a piped subshell reads the pipe.
    #[test]
    fn piped_commands_are_marked() {
        let piped: Vec<bool> = parse("a | b || c |& d ; e")
            .iter()
            .map(|c| c.piped)
            .collect();
        assert_eq!(piped, vec![false, true, false, true, false]);
        let piped: Vec<bool> = parse("a | (b; c) && d").iter().map(|c| c.piped).collect();
        assert_eq!(piped, vec![false, true, true, false]);
    }
}
