//! The scenario file of `tollgate bench` (L20).
//!
//! ```toml
//! [[scenario]]
//! name = "core"                 # [A-Za-z0-9._-]+, unique
//! worktrees = 2                 # worktrees that make this commit
//! retries = 1                   # commits of the same tree again (default 0)
//! edit = [
//!   { path = "crates/core/src/lib.rs", append = "\n// bench {worktree}.{round}\n" },
//!   { path = "docs/notes.md", write = "# Notes {scenario}\n" },
//! ]
//! ```
//!
//! An edit appends to a file or writes the whole file (parent dirs are
//! created). `{worktree}` (index from 0), `{round}` (from 0) and
//! `{scenario}` in the text are replaced; other braces stay, so code
//! can be appended as it is. Give each worktree and round its own text
//! when each commit must have its own tree.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

/// The most worktrees one bench may create.
pub const MAX_WORKTREES: u32 = 64;

/// The parsed file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioFile {
    /// The scenarios, in file order.
    pub scenario: Vec<Scenario>,
}

/// One kind of commit.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    /// Name, for reports.
    pub name: String,
    /// How many worktrees make this commit.
    pub worktrees: u32,
    /// Commits of the same tree after the first (cache hits; L17 after a
    /// deny at the inline budget).
    #[serde(default)]
    pub retries: u32,
    /// The edits before each commit.
    pub edit: Vec<Edit>,
}

/// One file edit.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Edit {
    /// Path relative to the worktree root.
    pub path: String,
    /// Text appended to the file.
    #[serde(default)]
    pub append: Option<String>,
    /// Text that replaces the file.
    #[serde(default)]
    pub write: Option<String>,
}

/// Values of the placeholders for one edit.
#[derive(Debug, Clone, Copy)]
pub struct Place<'a> {
    /// Worktree index.
    pub worktree: u32,
    /// Round index.
    pub round: u32,
    /// Scenario name.
    pub scenario: &'a str,
}

fn fill(text: &str, at: Place<'_>) -> String {
    text.replace("{worktree}", &at.worktree.to_string())
        .replace("{round}", &at.round.to_string())
        .replace("{scenario}", at.scenario)
}

/// Refuses a path whose existing part is a symlink: a tree may hold a
/// link that leads out of the worktree.
fn no_symlink(root: &Path, rel: &str) -> std::io::Result<()> {
    let mut p = root.to_path_buf();
    for c in Path::new(rel).components() {
        p.push(c);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{} is a symlink", p.display()),
                ));
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Edit {
    /// Applies the edit in worktree `root`; returns the path it changed.
    pub fn apply(&self, root: &Path, at: Place<'_>) -> std::io::Result<PathBuf> {
        no_symlink(root, &self.path)?;
        let path = root.join(&self.path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        match (&self.append, &self.write) {
            (Some(text), None) => {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)?;
                f.write_all(fill(text, at).as_bytes())?;
            }
            (None, Some(text)) => std::fs::write(&path, fill(text, at))?,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "an edit needs exactly one of append, write",
                ));
            }
        }
        Ok(path)
    }
}

fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(format!(
            "scenario name {name:?}: use letters, digits, '.', '_' and '-'"
        ));
    }
    Ok(())
}

/// A relative path of normal components that does not enter `.git`.
fn check_path(path: &str) -> Result<(), String> {
    let p = Path::new(path);
    let normal = !path.is_empty()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
        && p.components().next() != Some(Component::Normal(".git".as_ref()));
    if normal && !path.contains('\0') {
        Ok(())
    } else {
        Err(format!(
            "edit path {path:?}: use a path relative to the worktree root, with no '..' and not in .git"
        ))
    }
}

impl ScenarioFile {
    /// Parses and validates `text`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let file: Self = toml::from_str(text).map_err(|e| e.to_string())?;
        file.validate()?;
        Ok(file)
    }

    /// Reads and validates `path`.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        Self::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    fn validate(&self) -> Result<(), String> {
        if self.scenario.is_empty() {
            return Err("no [[scenario]]".into());
        }
        let mut names = std::collections::BTreeSet::new();
        for s in &self.scenario {
            check_name(&s.name)?;
            if !names.insert(s.name.as_str()) {
                return Err(format!("scenario name {:?} is used twice", s.name));
            }
            if s.worktrees == 0 {
                return Err(format!(
                    "scenario {:?}: worktrees must be at least 1",
                    s.name
                ));
            }
            if s.edit.is_empty() {
                return Err(format!("scenario {:?}: no edit", s.name));
            }
            for e in &s.edit {
                check_path(&e.path).map_err(|m| format!("scenario {:?}: {m}", s.name))?;
                if e.append.is_some() == e.write.is_some() {
                    return Err(format!(
                        "scenario {:?}: edit of {:?} needs exactly one of append, write",
                        s.name, e.path
                    ));
                }
            }
        }
        let total = self.total_worktrees();
        if total > u64::from(MAX_WORKTREES) {
            return Err(format!(
                "the scenarios use {total} worktrees; at most {MAX_WORKTREES}"
            ));
        }
        Ok(())
    }

    /// The sum of the scenarios' worktree counts.
    #[must_use]
    pub fn total_worktrees(&self) -> u64 {
        self.scenario.iter().map(|s| u64::from(s.worktrees)).sum()
    }

    /// The scenario of each worktree, in file order.
    #[must_use]
    pub fn assignment(&self) -> Vec<&Scenario> {
        self.scenario
            .iter()
            .flat_map(|s| std::iter::repeat_n(s, s.worktrees as usize))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: &str = r#"
[[scenario]]
name = "core"
worktrees = 2
retries = 1
edit = [{ path = "src/lib.rs", append = "// {scenario} {worktree}.{round} {}\n" }]

[[scenario]]
name = "docs"
worktrees = 1
edit = [{ path = "docs/a.md", write = "x" }]
"#;

    #[test]
    fn parses_counts_and_assigns_worktrees_in_file_order_l20() {
        let f = ScenarioFile::parse(OK).unwrap();
        assert_eq!(f.total_worktrees(), 3);
        let names: Vec<&str> = f.assignment().iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["core", "core", "docs"]);
        assert_eq!(f.scenario[0].retries, 1);
        assert_eq!(f.scenario[1].retries, 0);
    }

    #[test]
    fn edits_fill_placeholders_and_keep_other_braces_l20() {
        let f = ScenarioFile::parse(OK).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let at = Place {
            worktree: 1,
            round: 2,
            scenario: "core",
        };
        let p = f.scenario[0].edit[0].apply(tmp.path(), at).unwrap();
        f.scenario[0].edit[0].apply(tmp.path(), at).unwrap();
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "// core 1.2 {}\n// core 1.2 {}\n"
        );
        let w = f.scenario[1].edit[0].apply(tmp.path(), at).unwrap();
        f.scenario[1].edit[0].apply(tmp.path(), at).unwrap();
        assert_eq!(std::fs::read_to_string(w).unwrap(), "x");
    }

    #[test]
    fn an_edit_never_follows_a_symlink_l20() {
        let tmp = tempfile::tempdir().unwrap();
        let wt = tmp.path().join("wt");
        let outside = tmp.path().join("outside");
        std::fs::create_dir_all(&wt).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, wt.join("dir")).unwrap();
        std::os::unix::fs::symlink(outside.join("f"), wt.join("file")).unwrap();
        let at = Place {
            worktree: 0,
            round: 0,
            scenario: "s",
        };
        for path in ["dir/x", "file"] {
            let e = Edit {
                path: path.into(),
                append: Some("x".into()),
                write: None,
            };
            let err = e.apply(&wt, at).unwrap_err();
            assert!(err.to_string().contains("symlink"), "{path}: {err}");
        }
        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    #[test]
    fn refuses_bad_names_paths_and_edits_l20() {
        let one = |name: &str, wt: u32, edit: &str| {
            format!("[[scenario]]\nname = \"{name}\"\nworktrees = {wt}\nedit = [{edit}]\n")
        };
        for (text, why) in [
            (
                one("a b", 1, "{ path = \"x\", append = \"1\" }"),
                "scenario name",
            ),
            (
                one("a", 0, "{ path = \"x\", append = \"1\" }"),
                "at least 1",
            ),
            (one("a", 1, ""), "no edit"),
            (one("a", 1, "{ path = \"../x\", append = \"1\" }"), "path"),
            (one("a", 1, "{ path = \"/x\", append = \"1\" }"), "path"),
            (one("a", 1, "{ path = \"./x\", append = \"1\" }"), "path"),
            (
                one("a", 1, "{ path = \".git/hooks/x\", append = \"1\" }"),
                "path",
            ),
            (one("a", 1, "{ path = \"x\" }"), "exactly one"),
            (
                one("a", 65, "{ path = \"x\", append = \"1\" }"),
                "at most 64",
            ),
            (
                "[[scenario]]\nname = \"a\"\nworktrees = 1\nedit = []\nextra = 1\n".into(),
                "unknown field",
            ),
            ("".into(), "scenario"),
            (
                format!(
                    "{}{}",
                    one("a", 1, "{ path = \"x\", write = \"1\" }"),
                    one("a", 1, "{ path = \"y\", write = \"1\" }")
                ),
                "used twice",
            ),
        ] {
            let e = ScenarioFile::parse(&text).unwrap_err();
            assert!(e.contains(why), "{why:?} in {e:?} for\n{text}");
        }
    }
}
