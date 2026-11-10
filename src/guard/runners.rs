//! Script runners the walker follows: the tools that run the command in
//! their arguments (`uv run`, `uvx`, `bunx`, `npx`) or a script of
//! `package.json` (`bun run`, `bun <script>`, `npm run`).

use super::cmds::{Arg, operands_at};

/// What a runner runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Runner {
    /// The command that starts at this index of the arguments.
    Argv(usize),
    /// The script with this name in `package.json` of the cwd.
    Script(String),
    /// Nothing the walker reads (`uv sync`, `bun test`).
    Data,
}

const UV_VALUED: &[&str] = &[
    "--with",
    "-p",
    "--python",
    "--project",
    "--directory",
    "--extra",
    "--group",
    "--env-file",
    "--package",
    "--index",
    "--with-requirements",
    "--with-editable",
    "--from",
];
const NPX_VALUED: &[&str] = &["-p", "--package", "-c", "--call"];
/// The subcommands of `bun` (and their aliases). Any other word is a
/// `package.json` script (`bun build` is the bundler, `bun ship` runs the
/// script `ship`): a built-in wins over a script of the same name.
const BUN_BUILTINS: &[&str] = &[
    "run",
    "test",
    "check",
    "fmt",
    "x",
    "repl",
    "exec",
    "install",
    "i",
    "add",
    "a",
    "remove",
    "rm",
    "update",
    "audit",
    "dedupe",
    "prune",
    "outdated",
    "link",
    "unlink",
    "publish",
    "patch",
    "patch-commit",
    "pm",
    "info",
    "why",
    "build",
    "init",
    "create",
    "c",
    "upgrade",
    "help",
    "completions",
    "discord",
    "feedback",
];

/// The runner `name args...`; `None` when `name` is not a runner.
#[must_use]
pub fn runner(name: &str, args: &[Arg]) -> Option<Runner> {
    let sub = args.first().and_then(Arg::lit);
    let after = |skip: usize, valued: &[&str]| {
        Runner::Argv(skip + operands_at(args.get(skip..).unwrap_or(&[]), valued))
    };
    Some(match (name, sub) {
        ("uv", Some("run")) => after(1, UV_VALUED),
        ("uv", Some("tool")) if args.get(1).and_then(Arg::lit) == Some("run") => {
            after(2, UV_VALUED)
        }
        ("uvx", _) => after(0, UV_VALUED),
        ("bunx" | "npx" | "pnpx", _) => after(0, NPX_VALUED),
        ("bun", Some("x")) => after(1, NPX_VALUED),
        ("npm" | "pnpm" | "yarn", Some("exec" | "dlx")) => after(1, NPX_VALUED),
        ("bun" | "npm" | "pnpm" | "yarn", Some("run" | "run-script")) => {
            let k = 1 + operands_at(&args[1..], &[]);
            match args.get(k).and_then(Arg::lit) {
                Some(script) => Runner::Script(script.to_owned()),
                None => Runner::Data,
            }
        }
        ("npm" | "pnpm" | "yarn", Some(s @ ("test" | "start"))) => Runner::Script(s.to_owned()),
        ("bun", Some(s)) if !s.starts_with('-') && !BUN_BUILTINS.contains(&s) => {
            Runner::Script(s.to_owned())
        }
        ("uv" | "bun" | "npm" | "pnpm" | "yarn", _) => Runner::Data,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(cmd: &str) -> Option<Runner> {
        let words: Vec<Arg> = cmd.split(' ').map(Arg::fixed).collect();
        runner(&words[0].s, &words[1..])
    }

    #[test]
    fn runners_give_the_inner_command_or_the_script_name() {
        assert_eq!(run("uv run pytest -q"), Some(Runner::Argv(1)));
        assert_eq!(run("uv run --with x -q git status"), Some(Runner::Argv(4)));
        assert_eq!(run("uv tool run ruff check"), Some(Runner::Argv(2)));
        assert_eq!(run("uvx --from pkg tool"), Some(Runner::Argv(2)));
        assert_eq!(run("bunx tsc --noEmit"), Some(Runner::Argv(0)));
        assert_eq!(run("npx -y -p pkg tool"), Some(Runner::Argv(3)));
        assert_eq!(run("bun x tsc"), Some(Runner::Argv(1)));
        assert_eq!(run("bun run build"), Some(Runner::Script("build".into())));
        assert_eq!(run("npm run -s lint"), Some(Runner::Script("lint".into())));
        assert_eq!(run("npm test"), Some(Runner::Script("test".into())));
        assert_eq!(run("bun test"), Some(Runner::Data));
        assert_eq!(run("bun ship"), Some(Runner::Script("ship".into())));
        assert_eq!(run("bun build"), Some(Runner::Data));
        assert_eq!(run("bun --version"), Some(Runner::Data));
        assert_eq!(run("uv sync"), Some(Runner::Data));
        assert_eq!(run("cargo run"), None);
    }
}
