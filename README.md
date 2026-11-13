# tollgate

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A commit gate for Claude Code sessions. It runs your checks on the exact tree that becomes a branch tip, and refuses the commit, merge or push when they did not pass.

You let Claude Code agents commit in your repos, often several at once, each in its own worktree. A pre-commit hook script is the usual gate, but it has gaps:

- The agent runs it, so the agent can skip it: `git commit --no-verify`, `-c core.hooksPath=...`, or a commit from a shell where the hook is not set.
- It checks the working tree, not what goes into the commit. Untracked and unstaged files can make a check pass or fail by mistake.
- It checks the same tree again on every retry and amend, and in every worktree. Ten agents can run the full test suite ten times at once, on one machine.
- A branch can change the config that judges it, for example by removing a lint step in the same commit.

tollgate closes these gaps for agent sessions. Your own terminal is not gated.

## What it does

- **Hooks for every git process of a session.** `tollgate install` adds the hook path to the `env` of `~/.claude/settings.json`. Each git process that a Claude session starts (Bash calls, scripts, `bash -c`) then runs tollgate's hooks. When a hook fails or is killed, git stops, so the gate fails closed.
- **Two tiers.** `fast` runs on every commit and checks what the change affects: the Rust crates that depend on the changed ones, the changed files for linters, the TypeScript and Python roots that changed. `full` checks everything. It runs on merges into `main`, `master` or `integration/*`, on pushes to a trusted remote, and in CI.
- **The exact tree.** Checks run on the tree from the git index, in a separate verify checkout with a clean environment. Untracked and dirty files never take part. Each agent worktree gets its own checkout, so its incremental build stays warm.
- **Results by tree.** A result is stored by tree hash, tier and a fingerprint of the toolchain and config. An identical tree is never checked twice. In `fast` jobs, a step whose inputs did not change reuses its last pass. Merges and pushes to `main` (and the other full refs) and CI run every step again, except a step that already ran and passed on that same tree. `tollgate check --rerun` runs only the steps that did not pass on the tree; `--rerun --all` runs every step.
- **Policy from the protected branch.** `tollgate.toml` and the tool configs come from the merge-base with the trusted `main`. A branch cannot weaken the checks that judge it. Its policy changes apply after it merges.
- **Shared slots.** Steps take host-wide slots (`cpu`, `pg`, ...) in a fair queue, so many agents do not overload one machine or one test database.
- **Short reports.** A deny prints the failing step, the failing tests or new diagnostics, one command to rerun, and `tollgate log <job> <step>` for the full log.
- **A Bash guard.** `tollgate guard` is a Claude Code PreToolUse hook. It denies commands that skip or change the hooks (`--no-verify`, `-c core.hooksPath`, ...), denies every Bash call while the gate is not armed, and asks before edits to policy files and settings. It is aimed at a careless agent, not a hostile one (see [Status](#status)).
- **Languages.** Rust (`cargo fmt`, clippy, nextest, doctests), TypeScript with Bun (biome, `tsc` or `svelte-check`, `bun test`) and Python with uv (ruff, pyright and pytest against a baseline). Without a `tollgate.toml`, tollgate detects the steps.

## Status

**0.1, early.** It is in trial on one Linux machine, on the author's own repos. Read this before you use it:

- **Not a security boundary.** tollgate runs as the same user as the agents. Its guard defends against a careless agent: one that, under pressure to finish, reaches for the direct, documented way round the gate. It does not defend against an agent that sets out to defeat it. The guarantee is not the guard: it is the git hooks, the tree-keyed record check at commit, merge and push, and the trusted anchor that picks the policy. A bypass is made visible. Keep branch protection and CI on your remote as the last line.
- **Linux first.** On macOS it builds and passes the whole test suite. macOS has no parent-death signal, so a watcher process per step kills the step when its runner dies. Still Linux-only: finding a lost job's processes by their environment (`TMPDIR`), and the subreaper. The latency budgets are per OS, larger on macOS (see [limits](docs/operations.md)).
- **GitLab CI only.** `tollgate ci-snippet` writes a GitLab CI job. There is no GitHub Actions snippet yet.
- **Commits without a `fast` check.** Commits made by `cherry-pick`, `revert`, `am`, `rebase` and fast-forward merges get no check when they are made. Push, `tollgate merge` and CI check them.
- **Nothing is gated until you say so.** The host config that `install` writes has no repos and no trusted remotes. Add them after install (see below).

Expect changes.

## Install

Requirements: Rust 1.89 or later, and Claude Code. Install from crates.io:

```sh
cargo install --locked tollgate
# or, from a clone:
cargo install --locked --path .
```

Then arm the gate from your own terminal:

```sh
tollgate install
tollgate doctor
```

`install` copies the binary to `$XDG_DATA_HOME/tollgate/bin/`, links the hooks next to it, writes the host config when it is absent, and shows a diff of `~/.claude/settings.json`. It asks before it changes the settings. Run it again after each `cargo install`.

To check that the hooks reach a session, run `tollgate doctor --injection` from a Bash call in a Claude session, in the main session and in a subagent. If the settings `env` does not reach one, the guard denies every Bash call there, so the gap fails closed.

To remove it, run `tollgate uninstall`. It removes exactly what `install` added. `tollgate gc --all` removes the stored results, logs and verify checkouts.

## Quick start

1. Edit the host config, `$XDG_CONFIG_HOME/tollgate/config.toml` (usually `~/.config/tollgate/config.toml`). The file that `install` writes gates no repo yet: `scope.remotes` and `scope.include` are empty. Set them for your machine:

   ```toml
   [scope]
   roots = ["~/Repos"]                                   # repos directly under these dirs are gated
   remotes = ["*github.com:you/*", "*github.com/you/*"]  # trusted remotes: full check on push
   include = ["myapp"]                                    # start with one repo; ["*"] for all
   exclude = []

   [resources]
   cpu = 3              # steps that use the cpu run at most 3 at a time
   pg = { slots = 2 }   # same for steps that use the test database

   [verify]
   # root = "/path/to/ssd/tollgate/verify"   # default: ~/.local/state/tollgate/verify
   max_checkouts = 12
   ```

   The other sections (`[nextest]`, `[budget]`, `[job]`) can stay as written.

   Add the remote of every repo you gate to `remotes`, with the URL as git has it (an ssh host alias included). Without a trusted remote, policy comes from the local `main`, and a commit whose base has no stored result runs every step. `tollgate doctor --repo .` warns about this.

2. Look at what tollgate detects in your repo:

   ```sh
   cd ~/Repos/myapp
   tollgate config --effective   # the config that jobs use, and what detection left out
   tollgate config init          # write it to tollgate.toml for review
   ```

3. Edit `tollgate.toml` as necessary and commit it. A small example for a Rust repo:

   ```toml
   version = 1

   [tiers]
   full_refs = ["main", "integration/*"]   # merges into these run the full tier

   [push]
   fast_refs = ["wip/*"]                   # pushes of these branches run only fast

   [select]
   docs_only = ["docs/**"]                 # commits that touch only these run no steps

   [[step]]
   name = "fmt"
   kind = "cargo-fmt"

   [[step]]
   name = "clippy"
   kind = "cargo-clippy"
   resources = ["cpu"]

   [[step]]
   name = "tests"
   kind = "nextest"
   resources = ["cpu", "pg"]

   [[step]]
   name = "migrations lint"
   kind = "command"
   run = "./scripts/lint-migrations.sh"
   tiers = ["full"]
   when = ["migrations/**"]
   ```

   `tollgate config --check` validates `tollgate.toml` and the host config. The full schema is in section 4.8 of [docs/spec.md](docs/spec.md).

4. Work as before. Agents commit with `git commit`; the gates run by themselves. Useful commands:

   | Command | Use |
   |---|---|
   | `tollgate check [--tier full] [--wait \| --detach] [--rerun [--all]]` | Check the index tree (or `--rev R`) before a commit or push. In an agent session, `--tier full` does not start a job (R104): it answers from a record or waits for a running job; a push starts the full tier. |
   | `tollgate run <step> [--rerun] [--wait \| --detach] [-- <args>...]` | Run one declared step, or get its stored pass on the same inputs (R105). Arguments narrow it. Its log and artefacts are printed. |
   | `tollgate wait <job>` | Wait for a job: exit 0 pass, 1 fail, 3 still running. |
   | `tollgate status` | Results and running jobs for `HEAD` and the index, and commits on the branch that have no result. |
   | `tollgate report <job>`, `tollgate log <job> <step>` | The full report and a step log. |
   | `tollgate merge <branch>` | Merge into a full ref with a `full` check before the commit. |

   When a check takes longer than the hook can wait, the hook denies and leaves the job running. The deny message gives one command that waits and then commits again.

## How it works

**Tiers and gates.** There are four gates. `pre-commit` runs `fast` on every commit. `pre-merge-commit` runs the tier of the target branch: `full` for a full ref. `pre-push` runs `full` for pushes to a trusted remote, unless `push.fast_refs` matches the branch. CI runs `tollgate run --tier full --here`, which you add with `tollgate ci-snippet --gitlab`.

**Results by tree.** A hook computes the tree of the index and looks for a stored result with the same tree, tier and fingerprint. On a hit, the hook answers at once. On a miss, it starts a job in the verify checkout for that worktree and waits for it up to its inline budget. Results are written only by the job runner. `tollgate audit` lists them for review.

**The guard.** The hooks run only when git sees the hook path from the session's `env`. An agent could remove it for one command. The guard is a PreToolUse hook on Bash, Write and Edit calls. It reads each command for the direct, documented bypasses only. It parses the Bash command as bash does and walks the commands that run, through the plain wrappers agents use every day: `&&` chains, subshells, `sh -c`, `eval`, `env`, `xargs`, `find -exec`, package script runners, and shell script files, also one the same command just wrote. Rules look at literal words in command position. Every other word is data, heredoc bodies and interpreter code included, so a commit message may name `--no-verify` or `GIT_CONFIG_COUNT`. It denies the hook-skip options, `-c` and environment overrides of the hooks path and `GIT_CONFIG_*`, force moves of a protected ref, writes into tollgate's dirs with ordinary tools (redirection, `cp`, `mv`, `rm`, `sed -i`, `tee`, ...), and `tollgate install`, `uninstall` and `remotes forget`. It asks you before edits to Claude settings, git config, git hooks and policy files. A part of a command that it cannot read and that names git, tollgate or `.claude` is an ask, not a deny; a command that names none of them is allowed at once. A commit made without the hooks is marked unverified, and later reports name it.

**What the guard does not try to stop.** Deliberate evasion is out of scope: obscure launchers, copied or renamed binaries, `PATH` changes, a pty made to fake a person, interpreter code, option abbreviations, aliases and functions that shadow a tool, and races. Parsing bash does not stop a hostile agent, so the guard does not try, and it is not a sandbox. Such a bypass still does not make the record check pass: a commit made without the hooks has no result record for its tree, so a push to a trusted remote that runs the `pre-push` hook, a merge that runs the hooks, and `tollgate merge` refuse it until its tree passes a check. The same interpreter code can also push or merge with the hooks skipped; then no record check runs on this machine, and only branch protection of `main` on the remote and CI stop it. That is why they are the backstop past the machine.

**Trust and scope.** A repo is in scope when it is a direct child of a `scope.roots` dir, or when a remote URL matches `scope.remotes`, and `scope.include`/`exclude` allow its name. Policy comes from the merge-base with the trusted remote's `main` (or `master`). tollgate asks the remote server for that branch with `git ls-remote` in a clean environment, so a locally written remote-tracking ref cannot pick the policy. Trust needs more than a scope match: the remote URL must be `https://`, `ssh://` or `git@host:path` with the pattern's exact host and path (`*` never crosses `/`), so a look-alike URL is gated but never trusted. A local mirror is trusted only by its exact path in `scope.trusted_paths`.

## Docs

- [docs/operations.md](docs/operations.md): the detailed reference. Gates, languages and detection, Python baselines, install details, daily use, CI, limits, rollout plan.
- [docs/benchmark.md](docs/benchmark.md): `tollgate bench`, which replays concurrent commits through the real hooks to choose resource slots.
- [docs/spec.md](docs/spec.md): the design specification and its requirements.

## Development

```sh
cargo test
```

Tests use real git repos, real child processes and real tools in temp dirs, with a sandbox `HOME`. They do not touch your Claude settings and use no network. A test whose tool (`bun`, `uv`, `pyright`, ...) is missing prints `SKIP` and passes.

## License

Apache-2.0. See [LICENSE](LICENSE).
