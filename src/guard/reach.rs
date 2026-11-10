//! Review G7/R25: whether a word bash expands at run time (a glob, a
//! brace list, `$'...'`) can name a path in tollgate's state, data or
//! config dir.
//!
//! The word becomes a list of tokens: literal characters, and the glob
//! and brace characters bash expands. Brace lists are expanded as text,
//! as bash does first; each result is then cut into the paths a program
//! may open ([`super::paths::path_candidates`]), and a candidate with a
//! glob is expanded against the file system, only along the dirs that
//! lead to one of tollgate's dirs, with links resolved.

use std::path::{Path, PathBuf};

use globset::GlobBuilder;

use super::paths;
use super::rules::Context;
use super::shell::{Part, Word};

/// A word character: literal, or one bash expands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tok {
    C(char),
    Meta(char),
}

/// Most brace results looked at for one word; past it the word is
/// treated as one that names tollgate's dirs.
const MAX_BRACE: usize = 256;

/// Most dir entries read for one glob.
const MAX_ENTRIES: usize = 20_000;

/// Private-use stand-ins for `*`, `?` and `[` that bash expands, so the
/// text can go through [`paths::path_candidates`].
const STAR: char = '\u{E000}';
const QUEST: char = '\u{E001}';
const CLASS: char = '\u{E002}';

/// The tokens of `w`, with `~` and variables from `lookup`; `None` when a
/// part is only known at run time (a substitution, an unknown variable).
pub fn tokens(w: &Word, home: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Option<Vec<Tok>> {
    let mut out = Vec::new();
    let lit = |out: &mut Vec<Tok>, s: &str| out.extend(s.chars().map(Tok::C));
    for (k, p) in w.parts.iter().enumerate() {
        match p {
            Part::Lit(s) => {
                for c in s.chars() {
                    // `\{` lost its backslash in the parse: taking it as a
                    // brace looks at more results, never fewer.
                    if w.brace && matches!(c, '{' | ',' | '}') {
                        out.push(Tok::Meta(c));
                    } else {
                        out.push(Tok::C(c));
                    }
                }
            }
            Part::Single(s) => lit(&mut out, s),
            Part::AnsiC(raw) => lit(&mut out, &ansi_c(raw)),
            Part::Glob(c) => out.push(Tok::Meta(*c)),
            Part::Tilde(u) if k == 0 && u.is_empty() => lit(&mut out, home),
            Part::Param(name, subs) if subs.is_empty() => {
                lit(&mut out, &lookup(super::shell::simple_param(name)?)?);
            }
            Part::Double(inner) => {
                for q in inner {
                    match q {
                        Part::Lit(s) => lit(&mut out, s),
                        Part::Param(name, subs) if subs.is_empty() => {
                            lit(&mut out, &lookup(super::shell::simple_param(name)?)?);
                        }
                        Part::CmdSub(s) => lit(&mut out, &s.cat_heredoc()?),
                        _ => return None,
                    }
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The brace expansions of `toks`, in order; `None` past [`MAX_BRACE`].
pub fn braces(toks: &[Tok]) -> Option<Vec<Vec<Tok>>> {
    let mut done = Vec::new();
    let mut todo = vec![toks.to_vec()];
    while let Some(t) = todo.pop() {
        match first_brace(&t) {
            None => done.push(t),
            Some((open, close, commas)) => {
                let head = &t[..open];
                let tail = &t[close + 1..];
                if commas.is_empty() {
                    // `{1..3}`, `{a..c}`: one name part, no `/`.
                    let mut n = head.to_vec();
                    n.push(Tok::Meta('*'));
                    n.extend_from_slice(tail);
                    todo.push(n);
                } else {
                    let mut bounds = vec![open];
                    bounds.extend(&commas);
                    bounds.push(close);
                    for w in bounds.windows(2) {
                        let mut n = head.to_vec();
                        n.extend_from_slice(&t[w[0] + 1..w[1]]);
                        n.extend_from_slice(tail);
                        todo.push(n);
                    }
                }
            }
        }
        if done.len() + todo.len() > MAX_BRACE {
            return None;
        }
    }
    done.reverse();
    Some(done)
}

/// The first brace list bash expands: `{`, its `}`, and its top-level
/// commas. A `{x..y}` sequence has no commas; a pair with neither is
/// literal text, so its braces are made literal and the search goes on.
fn first_brace(t: &[Tok]) -> Option<(usize, usize, Vec<usize>)> {
    let mut k = 0;
    while k < t.len() {
        if t[k] == Tok::Meta('{') {
            let mut depth = 0;
            let mut commas = Vec::new();
            for (j, tok) in t.iter().enumerate().skip(k) {
                match tok {
                    Tok::Meta('{') => depth += 1,
                    Tok::Meta('}') => {
                        depth -= 1;
                        if depth == 0 {
                            let inner: String = t[k + 1..j]
                                .iter()
                                .map(|x| match x {
                                    Tok::C(c) | Tok::Meta(c) => *c,
                                })
                                .collect();
                            if !commas.is_empty() || inner.contains("..") {
                                return Some((k, j, commas));
                            }
                            break;
                        }
                    }
                    Tok::Meta(',') if depth == 1 => commas.push(j),
                    _ => {}
                }
            }
        }
        k += 1;
    }
    None
}

/// `toks` as text, with glob characters as their stand-ins and literal
/// brace characters as themselves.
pub fn text(toks: &[Tok]) -> String {
    toks.iter()
        .map(|t| match t {
            Tok::Meta('*') => STAR,
            Tok::Meta('?') => QUEST,
            Tok::Meta('[') => CLASS,
            Tok::C(c) | Tok::Meta(c) => *c,
        })
        .collect()
}

/// True when `text` (from [`text`]) has a glob bash expands.
pub fn has_glob(text: &str) -> bool {
    text.contains([STAR, QUEST, CLASS])
}

/// One path component of [`text`] as a glob matcher.
fn component_glob(comp: &str) -> Option<globset::GlobMatcher> {
    let mut pat = String::new();
    let mut in_class = false;
    for c in comp.chars() {
        match c {
            STAR => pat.push('*'),
            QUEST => pat.push('?'),
            CLASS => {
                pat.push('[');
                in_class = true;
            }
            ']' if in_class => {
                pat.push(']');
                in_class = false;
            }
            c if in_class => pat.push(c),
            '*' | '?' | '[' | ']' | '{' | '}' | ',' | '\\' => {
                pat.push('[');
                pat.push(c);
                pat.push(']');
            }
            c => pat.push(c),
        }
    }
    GlobBuilder::new(&pat)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .ok()
        .map(|g| g.compile_matcher())
}

/// Where a path stands to tollgate's dirs.
enum Stand<'a> {
    /// In this dir.
    Inside(&'a PathBuf),
    /// Above this dir (not `/`, not above the home dir).
    Above(&'a PathBuf),
    /// On the way: `/` or a dir above the home dir.
    Way,
    Off,
}

fn stand<'a>(ctx: &'a Context, p: &Path) -> Stand<'a> {
    if let Some(d) = paths::tollgate_dir(ctx, p, false) {
        return Stand::Inside(d);
    }
    if let Some(d) = paths::reaches_tollgate_dir(ctx, p, true) {
        return Stand::Above(d);
    }
    if paths::tollgate_dir(ctx, p, true).is_some() {
        return Stand::Way;
    }
    Stand::Off
}

/// The path a glob candidate `text` (absolute, or relative to `cwd`) can
/// expand to in or above one of tollgate's dirs, and that dir. `Err`
/// when the glob reads more than [`MAX_ENTRIES`] entries.
pub fn glob_reach(
    ctx: &Context,
    cwd: Option<&Path>,
    text: &str,
) -> Result<Option<(PathBuf, PathBuf)>, ()> {
    let (start, rest) = match text.strip_prefix('/') {
        Some(r) => (PathBuf::from("/"), r),
        None => match cwd {
            Some(c) => (c.to_owned(), text),
            None => return Ok(None),
        },
    };
    let mut cur = vec![paths::canon(&start)];
    let mut read = 0usize;
    let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let mut next = Vec::new();
        for dir in &cur {
            match *comp {
                "." => next.push(dir.clone()),
                ".." => {
                    let mut p = dir.clone();
                    p.pop();
                    next.push(p);
                }
                c if !has_glob(c) => next.push(paths::canon(&dir.join(c))),
                c => {
                    let Some(m) = component_glob(c) else {
                        continue;
                    };
                    let Ok(entries) = std::fs::read_dir(dir) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        read += 1;
                        if read > MAX_ENTRIES {
                            return Err(());
                        }
                        if m.is_match(e.file_name()) {
                            next.push(paths::canon(&e.path()));
                        }
                    }
                }
            }
        }
        cur.clear();
        for p in next {
            match stand(ctx, &p) {
                Stand::Inside(d) => return Ok(Some((p.clone(), d.clone()))),
                Stand::Above(d) if last => return Ok(Some((p.clone(), d.clone()))),
                Stand::Above(_) | Stand::Way => cur.push(p),
                Stand::Off => {}
            }
        }
        if cur.is_empty() {
            return Ok(None);
        }
    }
    Ok(None)
}

/// R26: the Claude Code settings path ([`paths::claude_settings_word`])
/// a glob candidate `text` (absolute, or relative to `cwd`) can expand
/// to. A dir named `.claude` can be anywhere, so a step keeps every match
/// while a later component can be `.claude`; otherwise only matches that
/// lead to a user or managed settings dir or a `.claude` dir. `Err` when
/// the glob reads more than [`MAX_ENTRIES`] entries.
pub fn glob_claude(ctx: &Context, cwd: Option<&Path>, text: &str) -> Result<Option<PathBuf>, ()> {
    let (start, rest) = match text.strip_prefix('/') {
        Some(r) => (PathBuf::from("/"), r),
        None => match cwd {
            Some(c) => (c.to_owned(), text),
            None => return Ok(None),
        },
    };
    let comps: Vec<&str> = rest.split('/').filter(|c| !c.is_empty()).collect();
    let may_be_claude = |c: &str| {
        c.eq_ignore_ascii_case(".claude")
            || (has_glob(c) && component_glob(c).is_some_and(|m| m.is_match(".claude")))
    };
    let mut cur = vec![paths::canon(&start)];
    let mut read = 0usize;
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let later_claude = comps[i + 1..].iter().any(|c| may_be_claude(c));
        let mut next = Vec::new();
        for dir in &cur {
            match *comp {
                "." => next.push(dir.clone()),
                ".." => {
                    let mut p = dir.clone();
                    p.pop();
                    next.push(p);
                }
                c if !has_glob(c) => next.push(paths::canon(&dir.join(c))),
                c => {
                    let Some(m) = component_glob(c) else {
                        continue;
                    };
                    let Ok(entries) = std::fs::read_dir(dir) else {
                        continue;
                    };
                    for e in entries.flatten() {
                        read += 1;
                        if read > MAX_ENTRIES {
                            return Err(());
                        }
                        if m.is_match(e.file_name()) {
                            next.push(paths::canon(&e.path()));
                        }
                    }
                }
            }
        }
        if last {
            return Ok(next
                .into_iter()
                .find(|p| paths::claude_settings_word(ctx, p)));
        }
        cur = next
            .into_iter()
            .filter(|p| later_claude || paths::claude_settings(ctx, p).is_some())
            .collect();
        if cur.is_empty() {
            return Ok(None);
        }
    }
    Ok(None)
}

/// The text of `$'...'` as bash decodes it (`\c` is decoded as bash
/// does for letters; an escape it does not know stays as written).
#[must_use]
pub fn ansi_c(raw: &str) -> String {
    let c: Vec<char> = raw.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let digits = |from: usize, max: usize, radix: u32| -> (u32, usize) {
        let mut v = 0u32;
        let mut n = 0;
        while n < max {
            match c.get(from + n).and_then(|d| d.to_digit(radix)) {
                Some(d) => {
                    v = v * radix + d;
                    n += 1;
                }
                None => break,
            }
        }
        (v, n)
    };
    while i < c.len() {
        if c[i] != '\\' || i + 1 == c.len() {
            out.push(c[i]);
            i += 1;
            continue;
        }
        let e = c[i + 1];
        i += 2;
        let simple = match e {
            'a' => Some('\u{7}'),
            'b' => Some('\u{8}'),
            'e' | 'E' => Some('\u{1b}'),
            'f' => Some('\u{c}'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'v' => Some('\u{b}'),
            '\\' | '\'' | '"' | '?' => Some(e),
            _ => None,
        };
        if let Some(s) = simple {
            out.push(s);
            continue;
        }
        let (radix, max, from) = match e {
            'x' => (16, 2, i),
            'u' => (16, 4, i),
            'U' => (16, 8, i),
            '0'..='7' => (8, 3, i - 1),
            'c' => {
                if let Some(x) = c.get(i) {
                    out.push(char::from_u32(u32::from(*x) & 0x1f).unwrap_or('?'));
                    i += 1;
                } else {
                    out.push_str("\\c");
                }
                continue;
            }
            _ => {
                out.push('\\');
                out.push(e);
                continue;
            }
        };
        let (v, n) = digits(from, max, radix);
        if n == 0 {
            out.push('\\');
            out.push(e);
            continue;
        }
        i = from + n;
        // `\xHH` and octal give a byte; bash writes it as is, and a byte
        // past ASCII is not a path character the guard compares.
        out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_c_decodes_as_bash() {
        assert_eq!(ansi_c(r"/x/tollgat\x65"), "/x/tollgate");
        assert_eq!(ansi_c(r"\057x"), "/x");
        assert_eq!(ansi_c(r"tollgate"), "tollgate");
        assert_eq!(ansi_c(r"a\tb\\c\'"), "a\tb\\c'");
        assert_eq!(ansi_c(r"\q"), "\\q");
    }

    #[test]
    fn braces_expand_as_bash() {
        let t: Vec<Tok> = "a{b,c{d,e}}f"
            .chars()
            .map(|c| {
                if "{,}".contains(c) {
                    Tok::Meta(c)
                } else {
                    Tok::C(c)
                }
            })
            .collect();
        let mut all: Vec<String> = braces(&t).unwrap().iter().map(|x| text(x)).collect();
        all.sort();
        assert_eq!(all, ["abf", "acdf", "acef"]);
        let t: Vec<Tok> = "x{1..3}"
            .chars()
            .map(|c| {
                if "{}".contains(c) {
                    Tok::Meta(c)
                } else {
                    Tok::C(c)
                }
            })
            .collect();
        assert_eq!(braces(&t).unwrap().len(), 1);
        assert!(has_glob(&text(&braces(&t).unwrap()[0])));
    }
}
