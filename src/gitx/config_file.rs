//! A git config file parser with git's syntax rules (R7).
//!
//! A port of the rules in git's `config.c` (`git_parse_source`,
//! `get_base_var`, `get_extended_base_var`, `get_value`, `parse_value`), so
//! hooks can read `core.hooksPath` without a subprocess. Input that git would
//! reject is an error; the caller then asks git itself.

/// One `section[.subsection].key [= value]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Section name, lowercased, with a subsection appended as git does:
    /// `core`, `remote.origin`, `includeif.gitdir:~/x/`.
    pub section: String,
    /// Key name, lowercased.
    pub key: String,
    /// `None` for a bare key (boolean true).
    pub value: Option<String>,
}

impl Entry {
    /// True for `include.path` and `includeIf.<cond>.path`.
    #[must_use]
    pub fn is_include(&self) -> bool {
        self.key == "path" && (self.section == "include" || self.section.starts_with("includeif."))
    }
}

/// Parse error with git's line number.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct ParseError {
    /// 1-based line.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

struct Source<'a> {
    bytes: &'a [u8],
    pos: usize,
    line: usize,
    eof: bool,
}

fn iskeychar(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-'
}

/// git's `isspace` (sane_ctype): space, `\t`, `\n`, `\r`. Not `\v` or `\f`.
fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\r')
}

impl Source<'_> {
    /// git's `get_next_char`: `\r\n` reads as `\n`; end of input reads as
    /// `\n` and sets `eof`.
    fn next(&mut self) -> u8 {
        let Some(&c) = self.bytes.get(self.pos) else {
            if !self.eof {
                self.eof = true;
                self.line += 1;
            }
            return b'\n';
        };
        self.pos += 1;
        let c = if c == b'\r' && self.bytes.get(self.pos) == Some(&b'\n') {
            self.pos += 1;
            b'\n'
        } else {
            c
        };
        if c == b'\n' {
            self.line += 1;
        }
        c
    }

    fn err(&self, message: &str) -> ParseError {
        ParseError {
            line: self.line.max(1),
            message: message.to_owned(),
        }
    }
}

/// Parses a config file. Values must be UTF-8.
pub fn parse(bytes: &[u8]) -> Result<Vec<Entry>, ParseError> {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let mut src = Source {
        bytes,
        pos: 0,
        line: 1,
        eof: false,
    };
    let mut entries = Vec::new();
    let mut section: Option<String> = None;
    let mut comment = false;
    loop {
        let c = src.next();
        if c == b'\n' {
            if src.eof {
                return Ok(entries);
            }
            comment = false;
            continue;
        }
        if comment || isspace(c) {
            continue;
        }
        if c == b'#' || c == b';' {
            comment = true;
            continue;
        }
        if c == b'[' {
            section = Some(base_var(&mut src)?);
            continue;
        }
        if !c.is_ascii_alphabetic() {
            return Err(src.err("bad config line"));
        }
        let Some(sec) = &section else {
            return Err(src.err("key outside a section"));
        };
        let (key, value) = key_value(&mut src, c)?;
        entries.push(Entry {
            section: sec.clone(),
            key,
            value,
        });
    }
}

/// `[section]`, `[section "sub"]` or legacy `[section.sub]`.
fn base_var(src: &mut Source<'_>) -> Result<String, ParseError> {
    let mut name = String::new();
    loop {
        let c = src.next();
        if src.eof {
            return Err(src.err("unterminated section header"));
        }
        if c == b']' {
            return Ok(name);
        }
        if isspace(c) {
            return extended_base_var(src, name);
        }
        if !iskeychar(c) && c != b'.' {
            return Err(src.err("bad section name"));
        }
        name.push(char::from(c.to_ascii_lowercase()));
    }
}

fn extended_base_var(src: &mut Source<'_>, mut name: String) -> Result<String, ParseError> {
    let mut c = src.next();
    while c == b' ' || c == b'\t' {
        c = src.next();
    }
    if c != b'"' {
        return Err(src.err("bad section header"));
    }
    name.push('.');
    let mut sub = Vec::new();
    loop {
        let mut c = src.next();
        if c == b'\n' {
            return Err(src.err("unterminated subsection"));
        }
        if c == b'"' {
            break;
        }
        if c == b'\\' {
            c = src.next();
            if c == b'\n' {
                return Err(src.err("bad escape in subsection"));
            }
        }
        sub.push(c);
    }
    if src.next() != b']' {
        return Err(src.err("expected ] after subsection"));
    }
    name.push_str(&String::from_utf8(sub).map_err(|_| src.err("subsection is not UTF-8"))?);
    Ok(name)
}

fn key_value(src: &mut Source<'_>, first: u8) -> Result<(String, Option<String>), ParseError> {
    let mut key = String::from(char::from(first.to_ascii_lowercase()));
    let mut c;
    loop {
        c = src.next();
        if !iskeychar(c) {
            break;
        }
        key.push(char::from(c.to_ascii_lowercase()));
    }
    while c == b' ' || c == b'\t' {
        c = src.next();
    }
    if c == b'\n' {
        return Ok((key, None));
    }
    if c != b'=' {
        return Err(src.err("expected = after key"));
    }
    Ok((key, Some(value(src)?)))
}

fn value(src: &mut Source<'_>) -> Result<String, ParseError> {
    let mut out: Vec<u8> = Vec::new();
    let mut quote = false;
    let mut comment = false;
    let mut trim_len = 0usize;
    loop {
        let mut c = src.next();
        if c == b'\n' {
            if quote {
                return Err(src.err("unterminated quote"));
            }
            if trim_len > 0 {
                out.truncate(trim_len);
            }
            return String::from_utf8(out).map_err(|_| src.err("value is not UTF-8"));
        }
        if comment {
            continue;
        }
        if isspace(c) && !quote {
            if trim_len == 0 {
                trim_len = out.len();
            }
            if !out.is_empty() {
                out.push(c);
            }
            continue;
        }
        if !quote && (c == b';' || c == b'#') {
            comment = true;
            continue;
        }
        trim_len = 0;
        if c == b'\\' {
            c = src.next();
            match c {
                b'\n' => continue,
                b't' => c = b'\t',
                b'b' => c = 0x08,
                b'n' => c = b'\n',
                b'\\' | b'"' => {}
                _ => return Err(src.err("bad escape in value")),
            }
            out.push(c);
            continue;
        }
        if c == b'"' {
            quote = !quote;
            continue;
        }
        out.push(c);
    }
}

/// The last entry for `section.key` (last one wins, as in git).
#[must_use]
pub fn last<'a>(entries: &'a [Entry], section: &str, key: &str) -> Option<&'a Entry> {
    entries
        .iter()
        .rev()
        .find(|e| e.section == section && e.key == key)
}

/// git's boolean rules (`git_parse_maybe_bool`): a bare key is true; `true`,
/// `yes`, `on`, `1` and other non-zero integers are true; `false`, `no`,
/// `off`, `0` and the empty string are false. `None` when it is not a bool.
#[must_use]
pub fn parse_bool(value: Option<&str>) -> Option<bool> {
    let Some(v) = value else { return Some(true) };
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => Some(true),
        "false" | "no" | "off" | "" => Some(false),
        other => other.parse::<i64>().ok().map(|n| n != 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(text: &str) -> Entry {
        let e = parse(text.as_bytes()).unwrap();
        assert_eq!(e.len(), 1, "{e:?}");
        e.into_iter().next().unwrap()
    }

    #[test]
    fn sections_keys_and_case() {
        let e = parse(b"[Core]\n\tHooksPath = .githooks\n[remote \"Origin\"]\nurl = x\n[a.B]\nk\n")
            .unwrap();
        assert_eq!(
            e[0],
            Entry {
                section: "core".into(),
                key: "hookspath".into(),
                value: Some(".githooks".into())
            }
        );
        assert_eq!(e[1].section, "remote.Origin");
        assert_eq!(e[2].section, "a.b");
        assert_eq!(e[2].value, None);
    }

    #[test]
    fn values_quotes_escapes_comments_and_trim() {
        assert_eq!(
            one("[c]\nk = \"\\\"spaced dir\\\"  # comment\"\n")
                .value
                .unwrap(),
            "\"spaced dir\"  # comment"
        );
        assert_eq!(one("[c]\nk = a  b   # trailing\n").value.unwrap(), "a  b");
        assert_eq!(one("[c]\nk = a\\tb\\\\c\n").value.unwrap(), "a\tb\\c");
        assert_eq!(one("[c]\nk = one \\\n two\n").value.unwrap(), "one  two");
        assert_eq!(one("[c]\nk =\n").value.unwrap(), "");
        assert_eq!(one("[c]\nk = \" x \"\n").value.unwrap(), " x ");
        assert_eq!(one("[c] k = same line\n").value.unwrap(), "same line");
        assert_eq!(one("\u{feff}[c]\r\nk = crlf\r\n").value.unwrap(), "crlf");
        assert_eq!(one("; c\n# c\n[c]\nk = v").value.unwrap(), "v");
    }

    #[test]
    fn invalid_input_is_an_error() {
        for bad in [
            "[c\nk = v\n",
            "[c]\nk = \"open\n",
            "[c]\nk = \\q\n",
            "[c]\nk ; v\n",
            "k = v\n",
            "[c]\n1k = v\n",
            "[c \"sub]\n",
            "[c \"sub\"x]\n",
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn include_detection_and_last_wins() {
        let e = parse(b"[include]\npath = a\n[includeIf \"gitdir:~/x/\"]\npath = b\n[core]\nhooksPath = 1\nhooksPath = 2\n").unwrap();
        assert!(e[0].is_include() && e[1].is_include() && !e[2].is_include());
        assert_eq!(
            last(&e, "core", "hookspath").unwrap().value.as_deref(),
            Some("2")
        );
        assert!(last(&e, "core", "bare").is_none());
    }

    #[test]
    fn bools() {
        assert_eq!(parse_bool(None), Some(true));
        for t in ["true", "Yes", "on", "1", "42"] {
            assert_eq!(parse_bool(Some(t)), Some(true), "{t}");
        }
        for f in ["false", "NO", "off", "0", ""] {
            assert_eq!(parse_bool(Some(f)), Some(false), "{f}");
        }
        assert_eq!(parse_bool(Some("maybe")), None);
    }
}
