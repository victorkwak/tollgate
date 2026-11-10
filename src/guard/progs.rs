//! Programs whose own arguments can run commands or write files (G3, G7):
//! `sed` (the `e` command, the `e` and `w` flags of `s`, `w` and `W`),
//! `tar` (`--to-command`, `-I`, checkpoint actions, volume scripts),
//! `rg --pre`, `less +!cmd`, the vim family's command options, `gdb`
//! scripts, socat's `EXEC`/`SYSTEM`/`SHELL` addresses (its `socat-*.sh`
//! helper scripts are refused whole); Tcl (`tclsh`,
//! `wish`, `expect`) is refused whole (item 29). A program not listed here
//! runs as it is; its arguments are data to the guard.

/// What the arguments of a listed program do beyond reading.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Effects {
    /// Files the program writes (`sed 'w FILE'`).
    pub writes: Vec<String>,
    /// Script files the program reads its commands from (`sed -f FILE`),
    /// which the caller reads and checks with [`sed_script`].
    pub sed_files: Vec<String>,
}

/// Checks the arguments of `base` (`lits[0]` is the command name;
/// `None`: a word bash builds at run time whose value the guard does not
/// know).
///
/// # Errors
/// An argument that runs a command, or code the guard cannot read.
pub fn check(base: &str, lits: &[Option<String>]) -> Result<Effects, String> {
    match base {
        "sed" | "gsed" => sed_args(lits),
        "tar" | "gtar" | "bsdtar" => tar_args(base, lits).map(|()| Effects::default()),
        "rg" | "ripgrep" => {
            for a in lits.iter().skip(1).flatten() {
                if a == "--" {
                    break;
                }
                if a == "--pre" || a.starts_with("--pre=") {
                    return Err(
                        "rg --pre runs a program on every file it searches; the guard does not allow it (G3)"
                            .into(),
                    );
                }
            }
            Ok(Effects::default())
        }
        "less" | "more" | "most" => {
            for a in lits.iter().skip(1).flatten() {
                if a.starts_with('+') && a.contains('!') {
                    return Err(format!(
                        "{base} {a}: a `!` command in `+` runs a shell command (G3)"
                    ));
                }
            }
            Ok(Effects::default())
        }
        "vim" | "vi" | "nvim" | "ex" | "view" | "gvim" | "rvim" | "vimdiff" | "nvi" => {
            for a in lits.iter().skip(1) {
                let Some(a) = a else {
                    return Err(format!(
                        "{base} with a word bash builds at run time; the guard does not run an editor it cannot read (G3)"
                    ));
                };
                if a == "--" {
                    break;
                }
                if a.starts_with('+')
                    || matches!(a.as_str(), "-c" | "--cmd" | "-S" | "-s" | "-u" | "-x")
                    || a.starts_with("--cmd=")
                {
                    return Err(format!(
                        "{base} {a} runs editor commands, which can run a shell; the guard does not allow it (G3)"
                    ));
                }
            }
            Ok(Effects::default())
        }
        "gdb" | "lldb" => {
            for a in lits.iter().skip(1).flatten() {
                let name = a.split('=').next().unwrap_or(a);
                if matches!(
                    name,
                    "-ex"
                        | "-x"
                        | "-iex"
                        | "-ix"
                        | "--eval-command"
                        | "--command"
                        | "--init-eval-command"
                        | "--init-command"
                        | "-o"
                        | "-s"
                        | "--one-line"
                        | "--source"
                ) {
                    return Err(format!(
                        "{base} {a} runs debugger commands, which can run a shell; the guard does not allow it (G3)"
                    ));
                }
            }
            Ok(Effects::default())
        }
        b if versioned(b, "socat") => socat_args(lits).map(|()| Effects::default()),
        b if b.starts_with("socat-") && b.ends_with(".sh") => Err(format!(
            "{base} passes its words to socat after the shell splits them again; the guard cannot tell whether an address runs a program (G3, review note 10)"
        )),
        b if tcl(b) => Err(format!(
            "{base} runs Tcl code, which can run any program (`exec`, and `spawn` at a terminal it makes); the guard cannot read it (G3, item 29)"
        )),
        _ => Ok(Effects::default()),
    }
}

/// The Tcl interpreters and the `expect` family, versioned too
/// (`tclsh8.6`).
fn tcl(base: &str) -> bool {
    ["tclsh", "wish", "expectk", "expect", "jimsh"]
        .iter()
        .any(|stem| versioned(base, stem))
}

/// `base` is `stem` or `stem` with a version (`tclsh8.6`, `socat1`).
fn versioned(base: &str, stem: &str) -> bool {
    base.strip_prefix(stem)
        .is_some_and(|v| v.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

/// socat (item 29): an `EXEC`, `SYSTEM` or `SHELL` address runs a program,
/// with a pty when asked, so it could give a TTY-only command the
/// terminal it checks for. Address types are case-insensitive; a dual
/// address (`A!!B`) has two. A word built at run time is refused.
///
/// Every word is read as an address, options too (review note 10): a word
/// that starts with `-` can be a dual address (`-,ignoreeof!!SYSTEM:..`),
/// and an option or its value never starts with a program address type.
/// socat removes its own quotes and backslashes from the type
/// (`"SYSTEM"`, `SYS\TEM`, `'Sys'tem` all run), so the guard removes every
/// `'`, `"` and `\` before it reads the type. That only ever finds more:
/// a quoted or escaped `!!`, `:` or `,` does not split in socat, but it
/// does here. A `|` splits too: socat 2 chains addresses with it.
/// socat 1.8 installs the program as `socat1`; a version suffix is the
/// same program.
fn socat_args(lits: &[Option<String>]) -> Result<(), String> {
    for a in lits.iter().skip(1) {
        let Some(a) = a else {
            return Err(
                "socat with a word bash builds at run time; the guard cannot tell whether an address runs a program (G3)"
                    .into(),
            );
        };
        let bare: String = a
            .chars()
            .filter(|c| !matches!(c, '\'' | '"' | '\\'))
            .collect();
        for part in bare.split("!!").flat_map(|p| p.split('|')) {
            let kind = part
                .split([':', ','])
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase();
            if matches!(kind.as_str(), "exec" | "system" | "shell") {
                return Err(format!(
                    "socat {a}: an {} address runs a program; the guard does not allow it (G3, item 29)",
                    kind.to_ascii_uppercase()
                ));
            }
        }
    }
    Ok(())
}

/// `tar` options that run a program.
fn tar_args(base: &str, lits: &[Option<String>]) -> Result<(), String> {
    const LONG: &[&str] = &[
        "--to-command",
        "--use-compress-program",
        "--checkpoint-action",
        "--info-script",
        "--new-volume-script",
        "--rsh-command",
        "--rmt-command",
    ];
    let deny = |a: &str| {
        Err(format!(
            "{base} {a} runs a program the guard does not read (G3)"
        ))
    };
    for (k, a) in lits.iter().enumerate().skip(1) {
        let Some(a) = a.as_deref() else { continue };
        if a == "--" {
            break;
        }
        if let Some(long) = a.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or(long);
            // GNU tar takes any unique prefix of a long option; an
            // ambiguous one fails in tar anyway.
            if !name.is_empty() && LONG.iter().any(|l| l[2..].starts_with(name)) {
                return deny(a);
            }
            continue;
        }
        // `-I prog`, `-F script`, and the same letters in a cluster; the
        // first word is a cluster even without `-` (`tar xIf`).
        let cluster = a
            .strip_prefix('-')
            .or_else(|| (k == 1 && !a.contains('/')).then_some(a));
        if let Some(c) = cluster
            && c.chars().any(|c| c == 'I' || c == 'F')
        {
            return deny(a);
        }
    }
    Ok(())
}

/// GNU sed's long options; getopt takes any unique prefix of one.
const SED_LONG: &[&str] = &[
    "debug",
    "expression",
    "file",
    "follow-symlinks",
    "in-place",
    "line-length",
    "null-data",
    "zero-terminated",
    "posix",
    "quiet",
    "silent",
    "regexp-extended",
    "separate",
    "sandbox",
    "unbuffered",
    "help",
    "version",
];

/// The long option `name` names: itself, or the one option it is a
/// prefix of; `None` when it is unknown or ambiguous (sed then fails).
fn sed_long(name: &str) -> Option<&'static str> {
    if let Some(full) = SED_LONG.iter().find(|l| **l == name) {
        return Some(full);
    }
    let hits: Vec<&&str> = SED_LONG.iter().filter(|l| l.starts_with(name)).collect();
    match hits.as_slice() {
        [one] if !name.is_empty() => Some(one),
        _ => None,
    }
}

/// GNU `sed` options: the script (`-e`, `--expression`, or the first
/// operand) and script files (`-f`, `--file`).
fn sed_args(lits: &[Option<String>]) -> Result<Effects, String> {
    let mut fx = Effects::default();
    let mut scripts: Vec<String> = Vec::new();
    let mut given = false;
    let mut k = 1;
    let need = |lits: &[Option<String>], k: usize, what: &str| -> Result<String, String> {
        lits.get(k).cloned().flatten().ok_or_else(|| {
            format!("sed {what} with a word bash builds at run time; the guard reads only literal sed scripts (G3)")
        })
    };
    let mut operands = false;
    while k < lits.len() {
        let Some(a) = lits[k].as_deref() else {
            if !given && !operands {
                return Err(
                    "sed with a script bash builds at run time; the guard reads only literal sed scripts (G3)"
                        .into(),
                );
            }
            // A file operand.
            operands = true;
            k += 1;
            continue;
        };
        if operands || a == "-" || !a.starts_with('-') {
            if !given && !operands {
                scripts.push(a.to_owned());
                given = true;
            }
            operands = true;
            k += 1;
            continue;
        }
        if a == "--" {
            operands = true;
            k += 1;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, glued) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_owned())),
                None => (long, None),
            };
            let full = sed_long(name);
            if full == Some("expression") {
                let s = match glued {
                    Some(v) => v,
                    None => {
                        k += 1;
                        need(lits, k, "--expression")?
                    }
                };
                scripts.push(s);
                given = true;
            } else if full == Some("file") {
                let s = match glued {
                    Some(v) => v,
                    None => {
                        k += 1;
                        need(lits, k, "--file")?
                    }
                };
                fx.sed_files.push(s);
                given = true;
            } else if full == Some("line-length") && glued.is_none() {
                k += 1;
            }
            k += 1;
            continue;
        }
        let cluster = &a[1..];
        for (j, c) in cluster.char_indices() {
            let rest = &cluster[j + c.len_utf8()..];
            match c {
                'e' | 'f' | 'l' => {
                    let v = if rest.is_empty() {
                        k += 1;
                        need(lits, k, &format!("-{c}"))?
                    } else {
                        rest.to_owned()
                    };
                    match c {
                        'e' => {
                            scripts.push(v);
                            given = true;
                        }
                        'f' => {
                            fx.sed_files.push(v);
                            given = true;
                        }
                        _ => {}
                    }
                    break;
                }
                // `-i[SUFFIX]`: the rest of the word is the suffix.
                'i' => break,
                _ => {}
            }
        }
        k += 1;
    }
    for s in &scripts {
        fx.writes.extend(sed_script(s)?);
    }
    Ok(fx)
}

/// The files a GNU sed script writes (`w`, `W`, the `w` flag of `s`).
///
/// # Errors
/// A command that runs a shell command (`e`, the `e` flag of `s`), or a
/// script the guard cannot read.
pub fn sed_script(script: &str) -> Result<Vec<String>, String> {
    let c: Vec<char> = script.chars().collect();
    let mut i = 0;
    let mut writes = Vec::new();
    let bad = |what: &str| {
        Err(format!(
            "the guard cannot read this sed script ({what}); write it plainly or use another tool (G3)"
        ))
    };
    let exec = || {
        Err::<Vec<String>, String>(
            "sed `e` runs a shell command; the guard does not allow it (G3)".into(),
        )
    };
    // The rest of the line from `i`, for file names and text.
    let line = |i: &mut usize| -> String {
        let start = *i;
        while *i < c.len() && c[*i] != '\n' {
            *i += 1;
        }
        c[start..*i].iter().collect::<String>()
    };
    let skip_ws = |i: &mut usize| {
        while *i < c.len() && (c[*i] == ' ' || c[*i] == '\t') {
            *i += 1;
        }
    };
    // A delimited part (`/re/`): ends at an unescaped `delim`.
    let delimited = |i: &mut usize, delim: char| -> bool {
        while *i < c.len() {
            if c[*i] == '\\' {
                *i += 2;
                continue;
            }
            if c[*i] == delim {
                *i += 1;
                return true;
            }
            if c[*i] == '\n' && delim != '\n' {
                return false;
            }
            *i += 1;
        }
        false
    };
    let address = |i: &mut usize| -> Result<bool, ()> {
        if *i >= c.len() {
            return Ok(false);
        }
        match c[*i] {
            '0'..='9' => {
                while *i < c.len() && c[*i].is_ascii_digit() {
                    *i += 1;
                }
                if *i < c.len() && c[*i] == '~' {
                    *i += 1;
                    while *i < c.len() && c[*i].is_ascii_digit() {
                        *i += 1;
                    }
                }
                Ok(true)
            }
            '$' => {
                *i += 1;
                Ok(true)
            }
            '/' | '\\' => {
                let d = if c[*i] == '\\' {
                    *i += 1;
                    match c.get(*i) {
                        Some(&d) if d != '\n' && d != '\\' => d,
                        _ => return Err(()),
                    }
                } else {
                    '/'
                };
                *i += 1;
                if !delimited(i, d) {
                    return Err(());
                }
                while *i < c.len() && (c[*i] == 'I' || c[*i] == 'M') {
                    *i += 1;
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    };
    while i < c.len() {
        match c[i] {
            ' ' | '\t' | '\n' | ';' => {
                i += 1;
                continue;
            }
            '#' => {
                line(&mut i);
                continue;
            }
            _ => {}
        }
        // Addresses: `a1`, `a1,a2`, `a1,+N`, `a1,~N`, then `!`.
        match address(&mut i) {
            Err(()) => return bad("an address"),
            Ok(true) => {
                skip_ws(&mut i);
                if i < c.len() && c[i] == ',' {
                    i += 1;
                    skip_ws(&mut i);
                    if i < c.len() && (c[i] == '+' || c[i] == '~') {
                        i += 1;
                        while i < c.len() && c[i].is_ascii_digit() {
                            i += 1;
                        }
                    } else if !matches!(address(&mut i), Ok(true)) {
                        return bad("an address range");
                    }
                }
            }
            Ok(false) => {}
        }
        skip_ws(&mut i);
        while i < c.len() && c[i] == '!' {
            i += 1;
            skip_ws(&mut i);
        }
        let Some(&cmd) = c.get(i) else {
            return bad("an address without a command");
        };
        i += 1;
        match cmd {
            '{' | '}' | '=' | 'd' | 'D' | 'g' | 'G' | 'h' | 'H' | 'n' | 'N' | 'p' | 'P' | 'x'
            | 'z' | 'F' => {}
            'q' | 'Q' | 'l' | 'L' => {
                skip_ws(&mut i);
                while i < c.len() && c[i].is_ascii_digit() {
                    i += 1;
                }
            }
            // Text to the end of the line; `a\` continues on lines that end
            // with a backslash.
            'a' | 'i' | 'c' => loop {
                let t = line(&mut i);
                let escaped = t.chars().rev().take_while(|&ch| ch == '\\').count() % 2 == 1;
                if !escaped || i >= c.len() {
                    break;
                }
                i += 1;
            },
            ':' | 'b' | 't' | 'T' | 'v' => {
                while i < c.len() && c[i] != '\n' && c[i] != ';' {
                    i += 1;
                }
            }
            'r' | 'R' => {
                line(&mut i);
            }
            'w' | 'W' => {
                skip_ws(&mut i);
                writes.push(line(&mut i));
            }
            'e' => return exec(),
            's' | 'y' => {
                let Some(&d) = c.get(i) else {
                    return bad("an s or y command without a delimiter");
                };
                if d == '\n' || d == '\\' {
                    return bad("an s or y delimiter");
                }
                i += 1;
                if !delimited(&mut i, d) || !delimited_text(&c, &mut i, d) {
                    return bad("an s or y command that does not end");
                }
                if cmd == 's' {
                    while i < c.len() {
                        match c[i] {
                            'g' | 'p' | 'i' | 'I' | 'm' | 'M' | '0'..='9' => i += 1,
                            'e' => return exec(),
                            'w' => {
                                i += 1;
                                skip_ws(&mut i);
                                writes.push(line(&mut i));
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            }
            _ => return bad(&format!("the command `{cmd}`")),
        }
    }
    for w in &writes {
        if w.is_empty() {
            return bad("`w` without a file");
        }
    }
    Ok(writes
        .into_iter()
        .filter(|w| w != "/dev/stdout" && w != "/dev/stderr")
        .collect())
}

/// The replacement part of `s` or the second part of `y`: like a
/// delimited part, but an escaped newline is part of it.
fn delimited_text(c: &[char], i: &mut usize, delim: char) -> bool {
    while *i < c.len() {
        if c[*i] == '\\' {
            *i += 2;
            continue;
        }
        if c[*i] == delim {
            *i += 1;
            return true;
        }
        if c[*i] == '\n' {
            return false;
        }
        *i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socat_program_addresses_are_found_in_every_word() {
        let l = |v: &[&str]| -> Vec<Option<String>> {
            v.iter().map(|s| Some((*s).to_owned())).collect()
        };
        for args in [
            &["socat", "-", "SYSTEM:id"][..],
            &["socat", "-u", "/dev/null", "exec:id,pty"],
            &["socat", "-", "SHELL"],
            &["socat", "-", "STDIN!!SYSTEM:id"],
            &["socat", "-", "-!!SYSTEM:id"],
            // Review note 10: a word that looks like an option.
            &["socat", "-", "-,ignoreeof!!SYSTEM:id"],
            &["socat", "-,ignoreeof!!EXEC:id", "/dev/null"],
            &["socat", "-d", "-d", "-,ign\\oreeof!!a!!Shell:id", "-"],
            // socat's own quoting and escaping.
            &["socat", "-", "\\SYSTEM:id"],
            &["socat", "-", "SYS\\TEM:id"],
            &["socat", "-", "\"SYSTEM\":id"],
            &["socat", "-", "'Sys'tem:id"],
            &["socat", "-", "-!'!'EXEC:id"],
            &["socat", "-", "-!\\!EXEC:id"],
        ] {
            assert!(check("socat", &l(args)).is_err(), "{args:?}");
        }
        for args in [
            &["socat", "-d", "-d", "-u", "/dev/null", "OPEN:out,creat"][..],
            &["socat", "-", "TCP:localhost:80"],
            &["socat", "-lf", "exec.log", "-", "UNIX-CONNECT:/tmp/s"],
            &["socat", "-,ignoreeof", "/dev/null"],
            &["socat", "-T", "5", "-", "OPEN:shell.txt"],
        ] {
            assert!(check("socat", &l(args)).is_ok(), "{args:?}");
        }
        assert!(check("socat", &[Some("socat".into()), Some("-".into()), None]).is_err());
        // Other names of the same program, and socat 2 address chains.
        assert!(check("socat1", &l(&["socat1", "-", "SYSTEM:id"])).is_err());
        assert!(check("socat2", &l(&["socat2", "-", "TCP:h:1|EXEC:id"])).is_err());
        assert!(check("socat1", &l(&["socat1", "-", "TCP:h:1"])).is_ok());
        assert!(check("socatx", &l(&["socatx", "-", "SYSTEM:id"])).is_ok());
        // The helper scripts split their option words again in a shell.
        for b in ["socat-chain.sh", "socat-mux.sh", "socat-broker.sh"] {
            assert!(
                check(b, &l(&[b, "-d -d", "TCP-L:1", "TCP:h:1"])).is_err(),
                "{b}"
            );
        }
    }

    #[test]
    fn sed_scripts_that_run_commands_are_denied() {
        for s in [
            "1e git commit -n -m x",
            "e",
            "s/x/git commit -n/e",
            "s|x|y|ge",
            "/a/,/b/ { s/x/y/e }",
            "1!e date",
            "$ e",
            "s/a/b/;e",
        ] {
            assert!(sed_script(s).is_err(), "{s}");
        }
    }

    #[test]
    fn sed_scripts_that_only_edit_are_read() {
        for s in [
            "s/a/b/g",
            "s/--no-verify/x/; s|a/b|c|",
            "1,40p",
            "/^$/d",
            "s/e/E/g",
            "/start/,/end/{s/x/y/;p}",
            "$a\\\nlast line",
            "1i hello e",
            "y/abc/xyz/",
            "s/a\\/b/c/2",
            "\\#x#d",
            "/x/I,+3 d",
            "0~4 p",
            "s/a/b\\\nc/",
            "# comment e\np",
            ":a;N;$!ba;s/\\n/ /g",
        ] {
            assert_eq!(sed_script(s), Ok(Vec::new()), "{s}");
        }
        assert_eq!(
            sed_script("s/a/b/w out.txt"),
            Ok(vec!["out.txt".to_owned()])
        );
        assert_eq!(sed_script("1w .git/HEAD"), Ok(vec![".git/HEAD".to_owned()]));
        assert_eq!(sed_script("p;w /dev/stdout"), Ok(Vec::new()));
    }

    #[test]
    fn sed_options_find_every_script() {
        let l = |v: &[&str]| -> Vec<Option<String>> {
            v.iter().map(|s| Some((*s).to_owned())).collect()
        };
        assert!(check("sed", &l(&["sed", "-n", "-e", "p", "-e", "1e id", "f"])).is_err());
        assert!(check("sed", &l(&["sed", "--expression=1e id", "f"])).is_err());
        assert!(check("sed", &l(&["sed", "--e=1e id", "f"])).is_err());
        assert!(check("sed", &l(&["sed", "--exp", "1e id", "f"])).is_err());
        assert!(
            check("sed", &l(&["sed", "--fi", "x.sed", "f"]))
                .unwrap()
                .sed_files
                .len()
                == 1
        );
        assert!(check("sed", &l(&["sed", "-ne1e id", "f"])).is_err());
        assert!(check("sed", &l(&["sed", "-i.bak", "1e id", "f"])).is_err());
        assert!(check("sed", &l(&["sed", "-i", "s/a/b/", "--", "e"])).is_ok());
        assert!(check("sed", &[Some("sed".into()), None, Some("f".into())]).is_err());
        assert!(check("sed", &[Some("sed".into()), Some("p".into()), None]).is_ok());
        assert_eq!(
            check("sed", &l(&["sed", "-f", "x.sed", "f"]))
                .unwrap()
                .sed_files,
            vec!["x.sed".to_owned()]
        );
        assert!(
            check(
                "tar",
                &l(&["tar", "-cf", "/dev/null", "--to-command=id", "."])
            )
            .is_err()
        );
        assert!(check("tar", &l(&["tar", "--to-co=id", "-xf", "a.tar"])).is_err());
        assert!(check("tar", &l(&["tar", "--rs=x", "-xf", "a.tar"])).is_err());
        assert!(check("tar", &l(&["tar", "--use=zstd", "-xf", "a.tar"])).is_err());
        assert!(check("tar", &l(&["tar", "xIf", "zstd", "a.tar"])).is_err());
        assert!(check("tar", &l(&["tar", "-czf", "a.tgz", "dir"])).is_ok());
        assert!(check("rg", &l(&["rg", "--pre", "./f", "x"])).is_err());
        assert!(check("rg", &l(&["rg", "-n", "--", "--pre"])).is_ok());
        assert!(check("less", &l(&["less", "+!id", "f"])).is_err());
        assert!(check("vim", &l(&["vim", "-c", "!id", "f"])).is_err());
        assert!(check("gdb", &l(&["gdb", "-batch", "-ex", "shell id"])).is_err());
    }
}
