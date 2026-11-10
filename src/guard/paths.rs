//! Paths for the guard's write rules (R25, G7, G8, item 15).
//!
//! A path a command writes is made absolute against the tracked cwd,
//! `.` and `..` are applied, and the longest existing prefix is resolved
//! through symlinks, so a link into tollgate's dirs or into `.git` does
//! not hide the target.

use std::path::{Component, Path, PathBuf};

use super::rules::Context;

/// `path` made absolute against `cwd`, with `.` and `..` removed
/// lexically.
#[must_use]
pub fn lexical(cwd: &Path, path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_owned()
    } else {
        cwd.join(path)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// `path` (absolute) with symlinks resolved as the kernel resolves them:
/// each `..` applies to the resolved dir before it, and the longest
/// existing prefix of the result is canonical. The rest is kept as
/// written.
#[must_use]
pub fn canon(path: &Path) -> PathBuf {
    let mut out = PathBuf::from("/");
    for c in path.components() {
        match c {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                if let Ok(r) = std::fs::canonicalize(&out) {
                    out = r;
                }
                out.pop();
            }
            Component::Normal(n) => out.push(n),
        }
    }
    let mut tail = Vec::new();
    let mut cur = out.clone();
    loop {
        if let Ok(mut r) = std::fs::canonicalize(&cur) {
            for t in tail.iter().rev() {
                r.push(t);
            }
            return r;
        }
        match cur.file_name() {
            Some(n) => {
                tail.push(n.to_owned());
                cur.pop();
            }
            None => return out,
        }
    }
}

/// Lowercase text of a path (APFS is case-insensitive).
#[must_use]
pub fn lower(p: &Path) -> String {
    p.to_string_lossy().to_lowercase()
}

/// True when `path` is inside `dir`, or (for removals) `dir` is inside
/// `path`. Case-insensitive.
fn touches(path: &Path, dir: &Path, removal: bool) -> bool {
    let p = lower(path);
    let d = lower(dir);
    let inside = |a: &str, b: &str| a == b || a.starts_with(&format!("{b}/"));
    inside(&p, &d) || (removal && inside(&d, &p))
}

/// The tollgate dir (state, data, config) that a write of `path` touches.
#[must_use]
pub fn tollgate_dir<'a>(ctx: &'a Context, path: &Path, removal: bool) -> Option<&'a PathBuf> {
    ctx.protected.iter().find(|d| touches(path, d, removal))
}

/// Review G7/R25: the tollgate dir that a program given `path` can write:
/// `path` is in it, or `path` is a dir above it (`tar -x -C
/// ~/.local/share`, `cp -r x/. ~`) and `spelled_as_path` (the text has a
/// `/` or starts with `.` or `~`). `/` and the dirs above the home dir
/// are left out, and so is a bare name (`config` in `git config`): `/` is
/// a word in many commands that name no path (`tr / _`, `cut -d/`, `awk
/// -F/`), `/home` and `/tmp` hold everyone's files, and a bare name
/// reaches a dir above tollgate's only from a cwd that
/// [`above_tollgate_dir`] covers.
#[must_use]
pub fn reaches_tollgate_dir<'a>(
    ctx: &'a Context,
    path: &Path,
    spelled_as_path: bool,
) -> Option<&'a PathBuf> {
    if let Some(d) = tollgate_dir(ctx, path, false) {
        return Some(d);
    }
    if !spelled_as_path {
        return None;
    }
    let p = lower(path);
    let p = p.trim_end_matches('/');
    let d = tollgate_dir(ctx, path, true)?;
    // Only now the home dir's real path: most paths are below no
    // tollgate dir.
    let home = lower(&canon(&ctx.home));
    (!p.is_empty() && !home.starts_with(&format!("{p}/"))).then_some(d)
}

/// Review G7/R25: the tollgate dir that cwd `cwd` lies above, when `cwd`
/// is not `/`, the home dir or a dir above it (`~/.local`,
/// `~/.local/state`, `~/.config`): there a bare name (`share`, `state`)
/// names a dir that holds tollgate's.
#[must_use]
pub fn above_tollgate_dir<'a>(ctx: &'a Context, cwd: &Path) -> Option<&'a PathBuf> {
    let home = lower(&canon(&ctx.home));
    let c = lower(cwd);
    let c = c.trim_end_matches('/');
    if c.is_empty() || home == c || home.starts_with(&format!("{c}/")) {
        return None;
    }
    ctx.protected
        .iter()
        .find(|d| lower(d).starts_with(&format!("{c}/")))
}

/// Review G7/R25: true when `text` (a command, or a script it runs)
/// spells one of tollgate's dirs: its path, or that path with the home dir
/// as `~`, `$HOME` or `${HOME}`, or with an XDG base dir as
/// `$XDG_..._HOME` or `${XDG_..._HOME}`, followed by the end, `/` or a
/// character that cannot go on a dir name in a shell word (`tollgate-x`
/// and `tollgate.bak` are other dirs). Case-insensitive.
#[must_use]
pub fn spells_tollgate_dir(ctx: &Context, text: &str) -> bool {
    let low = text.to_lowercase();
    if !low.contains("tollgate") {
        return false;
    }
    let mut forms: Vec<String> = Vec::new();
    for d in &ctx.protected {
        let d = lower(d);
        forms.push(d.clone());
        for (var, value) in &ctx.vars {
            let v = lower(Path::new(value));
            let v = v.trim_end_matches('/');
            if v.is_empty() {
                continue;
            }
            if let Some(rest) = d.strip_prefix(&format!("{v}/")) {
                let var = var.to_lowercase();
                forms.push(format!("${var}/{rest}"));
                forms.push(format!("${{{var}}}/{rest}"));
                if var == "home" {
                    forms.push(format!("~/{rest}"));
                }
            }
        }
    }
    forms.iter().any(|f| {
        low.match_indices(f.as_str()).any(|(k, _)| {
            low[k + f.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.')))
        })
    })
}

/// Review G7/R25: true when `raw` (a word bash builds at run time, as
/// written) holds the last two names of one of tollgate's dirs
/// (`state/tollgate`, `share/tollgate`, `.config/tollgate`) or an XDG
/// variable followed by `/tollgate` (`$X_HOME/tollgate`), then the end or
/// a character that cannot go on a dir name. `target/debug/tollgate` and
/// `~/Repos/tollgate` do not count.
#[must_use]
pub fn spells_tollgate_tail(ctx: &Context, raw: &str) -> bool {
    let low = raw.to_lowercase();
    if !low.contains("tollgate") {
        return false;
    }
    let mut tails: Vec<String> = vec!["_home/tollgate".into(), "_home}/tollgate".into()];
    for d in &ctx.protected {
        if let (Some(n), Some(p)) = (d.file_name(), d.parent().and_then(Path::file_name)) {
            tails.push(format!("{}/{}", p.to_string_lossy(), n.to_string_lossy()).to_lowercase());
        }
    }
    tails.iter().any(|f| {
        low.match_indices(f.as_str()).any(|(k, _)| {
            low[k + f.len()..]
                .chars()
                .next()
                .is_none_or(|c| !(c.is_alphanumeric() || matches!(c, '-' | '_' | '.')))
        })
    })
}

/// Review G7/R25: every text in argument `v` (its value as bash passes
/// it) that a program may open as a path: the whole word (not an
/// option), the value after each `=` (`--output=P`, `DESTDIR=P`), each
/// part between `,` and `:` (`-Wl,-o,P`, `file://P`, `PATH`-like
/// lists), and for a short option word every glued tail (`-oP`, `-uoP`).
/// A leading `~` is also tried as the home dir: bash expands it after
/// the `=` of a `NAME=` word and after `:` there, and a program may.
#[must_use]
pub fn path_candidates(v: &str, home: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut push = |t: &str| {
        if t.is_empty() || t == "-" || t == "--" {
            return;
        }
        if t == "~" {
            out.push(home.to_owned());
        } else if let Some(rest) = t.strip_prefix("~/") {
            out.push(format!("{home}/{rest}"));
        }
        out.push(t.to_owned());
    };
    let option = v.starts_with('-');
    if !option {
        push(v);
    }
    for (k, c) in v.char_indices() {
        if matches!(c, '=' | ',' | ':') {
            let tail = &v[k + 1..];
            push(tail);
            push(tail.split([',', ':']).next().unwrap_or_default());
        }
    }
    for part in v.split([',', ':', '=']) {
        if !part.starts_with('-') {
            push(part);
        }
    }
    if option && !v.starts_with("--") {
        for (k, _) in v.char_indices().skip(2) {
            push(&v[k..]);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// G7: `.git/refs`, `.git/packed-refs`, `.git/config` or `.git/hooks`
/// (also inside them, and with `.git` of any case) when `path` is or is
/// under one of them, or a worktree's `config.worktree` under `.git`
/// (item 21); the name.
#[must_use]
pub fn git_internal(path: &Path) -> Option<&'static str> {
    let comps: Vec<String> = path
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_lowercase())
        .collect();
    let in_git = comps.iter().position(|c| c == ".git");
    if in_git.is_some_and(|k| comps[k + 1..].iter().any(|c| c == "config.worktree")) {
        return Some(".git/config.worktree");
    }
    comps.windows(2).find_map(|w| {
        if w[0] != ".git" {
            return None;
        }
        match w[1].as_str() {
            "refs" => Some(".git/refs"),
            "packed-refs" => Some(".git/packed-refs"),
            "config" => Some(".git/config"),
            "hooks" => Some(".git/hooks"),
            _ => None,
        }
    })
}

/// Item 21: git's global and system config files (`~/.gitconfig`,
/// `$XDG_CONFIG_HOME/git/config` and `~/.config/git/config`, which a
/// session without `XDG_CONFIG_HOME` reads, `$GIT_CONFIG_GLOBAL`,
/// `/etc/gitconfig`, `$GIT_CONFIG_SYSTEM`), which every git command reads
/// and whose program keys it runs, when a write of `path` replaces one:
/// the file itself, the file it links to, or a dir above it inside the
/// home dir (`mv x ~/.config/git`). The file's name.
#[must_use]
pub fn git_global_config(ctx: &Context, path: &Path) -> Option<PathBuf> {
    let xdg = ctx
        .var("XDG_CONFIG_HOME")
        .filter(|v| v.starts_with('/'))
        .map_or_else(|| ctx.home.join(".config"), PathBuf::from);
    let home = lower(&canon(&ctx.home));
    let p = lower(path);
    let mut files = vec![
        ctx.home.join(".gitconfig"),
        xdg.join("git/config"),
        ctx.home.join(".config/git/config"),
        PathBuf::from("/etc/gitconfig"),
    ];
    for v in ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"] {
        if let Some(f) = ctx.git_env.get_str(v).filter(|f| f.starts_with('/')) {
            files.push(PathBuf::from(f));
        }
    }
    files.into_iter().find(|f| {
        [lower(f), lower(&canon(f))].iter().any(|f| {
            p == *f || (f.starts_with(&format!("{p}/")) && p.starts_with(&format!("{home}/")))
        })
    })
}

/// The dirs Claude Code reads managed settings from (`managed-settings.json`
/// and the `managed-settings.d` drop-ins), on Linux and on macOS (Claude
/// Code 2.1.317 has no variable that moves them). Both are checked on
/// every host: a wrong-platform path costs a failed lookup once per call.
pub const MANAGED_SETTINGS_DIRS: [&str; 2] = [
    "/etc/claude-code",
    "/Library/Application Support/ClaudeCode",
];

/// The Claude Code settings locations of the session (R26), worked out
/// once per guard call (L19: every word of a program that is not a known
/// reader is checked against them). All lowercase, absolute, without a
/// trailing `/`.
#[derive(Debug, Clone, Default)]
pub struct ClaudePaths(std::sync::OnceLock<ClaudeRoots>);

#[derive(Debug, Clone)]
struct ClaudeRoots {
    /// The user settings dirs (`~/.claude`, `$CLAUDE_CONFIG_DIR`), as
    /// spelled and resolved.
    user: Vec<String>,
    /// What the user settings files (`settings.json`,
    /// `settings.local.json`) resolve to: a dotfiles copy they link to.
    user_files: Vec<String>,
    /// The managed settings dirs, as spelled and resolved, and what
    /// `managed-settings.json` and `managed-settings.d` resolve to: paths
    /// at or in them are settings.
    managed: Vec<String>,
    /// What each `managed-settings.d` entry resolves to.
    drop_ins: Vec<String>,
}

impl ClaudePaths {
    fn roots(&self, ctx: &Context) -> &ClaudeRoots {
        self.0.get_or_init(|| {
            let norm = |p: &Path| {
                let l = lower(p);
                match l.trim_end_matches('/') {
                    "" => l,
                    t => t.to_owned(),
                }
            };
            let mut dirs = vec![ctx.home.join(".claude")];
            if let Some(d) = ctx.var("CLAUDE_CONFIG_DIR").filter(|d| d.starts_with('/')) {
                dirs.push(PathBuf::from(d));
            }
            let mut r = ClaudeRoots {
                user: Vec::new(),
                user_files: Vec::new(),
                managed: Vec::new(),
                drop_ins: Vec::new(),
            };
            for d in &dirs {
                r.user.extend([norm(d), norm(&canon(d))]);
                for f in ["settings.json", "settings.local.json"] {
                    r.user_files.push(norm(&canon(&d.join(f))));
                }
            }
            for d in MANAGED_SETTINGS_DIRS.map(Path::new) {
                let drop_in = canon(&d.join("managed-settings.d"));
                r.managed.extend([
                    norm(d),
                    norm(&canon(d)),
                    norm(&canon(&d.join("managed-settings.json"))),
                    norm(&drop_in),
                ]);
                if let Ok(entries) = std::fs::read_dir(&drop_in) {
                    r.drop_ins
                        .extend(entries.flatten().map(|e| norm(&canon(&e.path()))));
                }
            }
            for v in [
                &mut r.user,
                &mut r.user_files,
                &mut r.managed,
                &mut r.drop_ins,
            ] {
                v.sort();
                v.dedup();
            }
            r
        })
    }
}

/// How a path stands to the Claude Code settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaudeHit {
    /// A settings file, a settings dir, or a path in a managed settings
    /// dir.
    Is,
    /// A dir that holds a user or managed settings dir.
    Holds,
}

fn claude_hit(ctx: &Context, path: &Path) -> Option<ClaudeHit> {
    let is_settings = |n: &str| {
        n.starts_with("settings")
            && std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json"))
    };
    let name = path.file_name().map(|n| n.to_string_lossy().to_lowercase());
    let settings_name = name.as_deref().is_some_and(is_settings);
    let parent = path.parent().map(lower);
    let parent_name = path
        .parent()
        .and_then(Path::file_name)
        .map(|n| n.to_string_lossy().to_lowercase());
    if (settings_name && parent_name.as_deref() == Some(".claude"))
        || name.as_deref() == Some(".claude")
    {
        return Some(ClaudeHit::Is);
    }
    let p = lower(path);
    let p = match p.trim_end_matches('/') {
        "" => "/",
        t => t,
    };
    let at_or_in = |d: &str| p == d || p.starts_with(&format!("{d}/"));
    let holds = |d: &str| d != p && (p == "/" || d.starts_with(&format!("{p}/")));
    let r = ctx.claude.roots(ctx);
    if r.user
        .iter()
        .any(|d| p == d || (settings_name && parent.as_deref() == Some(d.as_str())))
        || r.user_files.iter().any(|f| p == f)
        || r.managed.iter().any(|d| at_or_in(d))
        || r.drop_ins.iter().any(|f| p == f)
    {
        return Some(ClaudeHit::Is);
    }
    r.user
        .iter()
        .chain(&r.managed)
        .any(|d| holds(d))
        .then_some(ClaudeHit::Holds)
}

/// R26 (item 21 review, review of item 21): the Claude Code settings a
/// write of `path` changes. The user settings file registers the guard
/// and the hook injection (`GIT_CONFIG_*`) for every later session; a
/// project's settings can set the session environment too; managed
/// settings outrank every other file and can turn every user hook off
/// (`disableAllHooks`, `allowManagedHooksOnly`). Matches,
/// case-insensitively: a `settings*.json` file in a dir named `.claude`
/// or in the user settings dir (`~/.claude`, `$CLAUDE_CONFIG_DIR`, each
/// as spelled and resolved); the file a user settings file links to; a
/// dir named `.claude` itself or a user settings dir (a copy into it, a
/// move, link or removal of it); any path at or in a managed settings
/// dir ([`MANAGED_SETTINGS_DIRS`], as spelled and resolved), and what
/// `managed-settings.json`, `managed-settings.d` and its entries link
/// to; a dir that holds a user or managed settings dir (`cp -r x/. ~`,
/// `rm -rf ~`, `rm -rf /etc`). `path` is absolute, as spelled or
/// canonical. The matched path.
#[must_use]
pub fn claude_settings(ctx: &Context, path: &Path) -> Option<PathBuf> {
    claude_hit(ctx, path).map(|_| path.to_owned())
}

/// R26 for a program that is not a known reader and may write any path
/// it is given ([`claude_settings`] less a dir that only holds a
/// settings dir: `fd x ~` writes nothing there, as R25 has it for
/// tollgate's dirs).
#[must_use]
pub fn claude_settings_word(ctx: &Context, path: &Path) -> bool {
    claude_hit(ctx, path) == Some(ClaudeHit::Is)
}

/// A program run with `cwd` may write settings there: `cwd` is a dir
/// named `.claude`, a user settings dir, or at or in a managed settings
/// dir.
#[must_use]
pub fn claude_settings_dir(ctx: &Context, cwd: &Path) -> bool {
    claude_hit(ctx, cwd) == Some(ClaudeHit::Is)
}

/// R26: `text` spells a Claude Code settings name (`.claude`, a managed
/// settings name, the `$CLAUDE_CONFIG_DIR` path): a word bash builds at
/// run time in a command that does may name a settings path.
#[must_use]
pub fn spells_claude(ctx: &Context, text: &str) -> bool {
    let low = text.to_lowercase();
    [".claude", "managed-settings", "claude-code", "claudecode"]
        .iter()
        .any(|n| low.contains(n))
        || ctx
            .var("CLAUDE_CONFIG_DIR")
            .filter(|d| d.starts_with('/'))
            .map(|d| d.trim_end_matches('/').to_lowercase())
            .is_some_and(|d| !d.is_empty() && low.contains(&d))
}

/// R26, G7 (item 21 review): what interpreter code names that it may
/// write: Claude Code settings (user, project, `$CLAUDE_CONFIG_DIR`,
/// managed) or git's global config. `code` is lowercase. A raw-text
/// match, so a read counts too.
#[must_use]
pub fn config_named(ctx: &Context, code: &str) -> Option<&'static str> {
    let config_dir = ctx
        .var("CLAUDE_CONFIG_DIR")
        .filter(|d| d.starts_with('/'))
        .map(|d| {
            let d = PathBuf::from(d);
            [lower(&d), lower(&canon(&d))]
        });
    let names_config_dir = config_dir.iter().flatten().any(|d| {
        let d = d.trim_end_matches('/');
        !d.is_empty() && code.contains(d)
    });
    if (code.contains(".claude") || names_config_dir) && code.contains("settings") {
        Some("Claude Code settings")
    } else if code.contains("claude_config_dir") {
        Some("the Claude Code settings dir")
    } else if code.contains("managed-settings")
        || MANAGED_SETTINGS_DIRS
            .iter()
            .any(|d| code.contains(&d.to_lowercase()))
    {
        Some("Claude Code managed settings")
    } else if code.contains("gitconfig")
        || code.contains("git/config")
        || code.contains("git_config_global")
    {
        Some("git's global config")
    } else {
        None
    }
}

/// The ask reason for a write of `path` that changes Claude Code
/// settings (R26).
#[must_use]
pub fn settings_write_reason(how: &str, path: &Path) -> String {
    format!(
        "{how} changes Claude Code settings at {}, which register the guard and the hook injection for every later session; a person decides (R26)",
        path.display()
    )
}

/// Item 35, review note 12: the tool path ([`Context::tool_paths`]: a dir
/// of the job PATH, a tool home, a host tool config) that a write of
/// `path` changes: `path` is it or lies under it, or it lies under `path`
/// and `path` is the home dir or inside it (`cp -r x/. ~/.local`).
/// Case-insensitive.
#[must_use]
pub fn tool_path<'a>(ctx: &'a Context, path: &Path) -> Option<&'a PathBuf> {
    let home = lower(&canon(&ctx.home));
    let p = lower(path);
    let in_home = p == home || p.starts_with(&format!("{home}/"));
    ctx.tool_paths.iter().find(|t| {
        let t = lower(t);
        p == t || p.starts_with(&format!("{t}/")) || (in_home && t.starts_with(&format!("{p}/")))
    })
}

/// The ask reason for a write of `path` that changes tool path `tool`.
#[must_use]
pub fn tool_write_reason(how: &str, path: &Path, tool: &Path) -> String {
    format!(
        "{how} writes {} in {}, which gate jobs run, build from or read as tool config; a person decides (item 35)",
        path.display(),
        tool.display()
    )
}

/// G7 for a removal: `rm -rf .git` (or a dir above it) removes the refs
/// with it.
#[must_use]
pub fn holds_git_internals(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| n.eq_ignore_ascii_case(".git"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lexical_and_canonical_paths() {
        assert_eq!(
            lexical(Path::new("/w/r"), Path::new("../x/./y")),
            PathBuf::from("/w/x/y")
        );
        let tmp = tempfile::tempdir().unwrap();
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::os::unix::fs::symlink(&real, tmp.path().join("link")).unwrap();
        let c = canon(&tmp.path().join("link/new/file"));
        assert_eq!(c, std::fs::canonicalize(&real).unwrap().join("new/file"));
        // `..` after a symlink applies to the link's target.
        let c = canon(&tmp.path().join("link/../real/z"));
        assert_eq!(c, std::fs::canonicalize(&real).unwrap().join("z"));
    }

    #[test]
    fn path_candidates_find_glued_and_assigned_paths_review_g7() {
        let has = |v: &str, want: &str| {
            let c = path_candidates(v, "/h");
            assert!(c.iter().any(|x| x == want), "{v}: {c:?} lacks {want}");
        };
        has("/s/tollgate/x", "/s/tollgate/x");
        has("-o/s/tollgate/x", "/s/tollgate/x");
        has("-uo/s/tollgate/x", "/s/tollgate/x");
        has("-otollgate/x", "tollgate/x");
        has("--output=/s/tollgate/x", "/s/tollgate/x");
        has("--root=~/.local/share/tollgate", "/h/.local/share/tollgate");
        has("DESTDIR=~/.local/share", "/h/.local/share");
        has("PATH=/a:~/b", "/h/b");
        has("-Wl,-o,/s/tollgate/x", "/s/tollgate/x");
        has("file:///s/tollgate/x", "///s/tollgate/x");
        has("~", "/h");
        // An option word is no path; `--x` gets no glued tails.
        let c = path_candidates("--verbose", "/h");
        assert!(c.is_empty(), "{c:?}");
        assert!(path_candidates("-", "/h").is_empty());
    }

    #[test]
    fn git_internals_g7() {
        for p in [
            "/r/.git/refs/heads/main",
            "/r/.git/packed-refs",
            "/r/.git/config",
            "/r/.git/hooks/pre-commit",
            "/r/.GIT/refs/remotes/origin/main",
            "/r/.git/refs",
            "/r/.git/config.worktree",
            "/r/.git/worktrees/w/config.worktree",
        ] {
            assert!(git_internal(Path::new(p)).is_some(), "{p}");
        }
        for p in [
            "/r/.git/index.lock",
            "/r/.gitignore",
            "/r/refs/x",
            "/r/.git",
        ] {
            assert!(git_internal(Path::new(p)).is_none(), "{p}");
        }
    }
}
