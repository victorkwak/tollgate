# tollgate

tollgate gates the git ref updates that Claude Code sessions make. It runs a repo's checks on the exact tree that becomes a branch tip, records the result by tree hash, and refuses the update when the checks did not pass. It replaces `~/.claude/hooks/pre-commit-checks.sh`.

The design is [`docs/spec.md`](docs/spec.md) (v3). Requirement ids (`R<n>`, `L<n>`) in this file point into it. The "Lead decisions" at the top of the spec override the requirements below them.

## What it does

- **Git hooks, not command text.** `tollgate install` adds `core.hooksPath` to the `env` of `~/.claude/settings.json` (R3). Every `git` process that a Claude session starts (Bash calls, scripts, `bash -c`, `/usr/bin/git`) then runs tollgate's hooks. git aborts the operation when a hook fails or is killed, so the gate fails closed (R37).
- **Four hard gates (L1).**
  - `pre-commit`: tier `fast` on every commit, on every branch (R17).
  - `pre-merge-commit`: the tier of the target branch: `full` for `main`, `master`, `integration/*` (R27, L7).
  - `pre-push`: tier `full` for every branch pushed to a trusted remote (the GitLab projects in `scope.remotes`), unless `push.fast_refs` matches (R20).
  - CI: `tollgate run --tier full --here` in GitLab CI, with GitLab protection of `main` as the last line (R47, R73).
- **The exact tree.** A hook checks `git write-tree` of the index that git gave it, in a private verify checkout with a clean environment (R40-R43, R52). Dirty and untracked files never take part. Each agent worktree gets its own sticky checkout per tier, so its incremental build stays warm (L15).
- **Results by tree.** A record is keyed by tree, tier and a fingerprint of the toolchain, host config and job environment (R74). An identical tree is never checked twice. Steps with the same inputs reuse their stored pass (L16), except in `full` jobs for full refs and in CI.
- **Two tiers.** `fast` checks what a change affects: the reverse dependencies of the changed Rust crates, the changed files for linters, the TypeScript and Python roots that have changes (R55-R61). `full` checks everything.
- **Policy from a protected commit (L2).** `tollgate.toml`, `.config/nextest.toml`, the Python baselines, cargo, clippy and rustfmt configs come from the merge-base of the commit with `main` (or `master`) of the trusted remote. A branch cannot weaken the checks that judge it; its own policy changes apply after it merges. Reports print a `POLICY:` line when a branch changes policy files.
- **Shared resources.** Steps take host-wide slots (`cpu`, `pg`, ...) with `flock(2)` in a fair queue (R85, R86). CI jobs on the workstation take the same slots.
- **Reports an agent can act on.** A deny prints at most about 80 lines: the failing step, the failing tests or new diagnostics, one rerun command, and `tollgate log <job> <step>` for the full log (R91).
- **A guard.** `tollgate guard` is a Claude Code PreToolUse hook. It denies every Bash call while the gate is not armed (R24, L8), denies text that removes or evades the hooks (`--no-verify`, `-c core.hooksPath`, ...), and asks before edits to policy files and settings (R25, R26).

## Languages

| Root | Detected by | Steps (R65 detection) | Setup (R45) |
|---|---|---|---|
| Rust | `Cargo.toml` | `fmt`, `clippy`, `tests` (nextest), `doctests` | none |
| TypeScript/Bun | `package.json` and `bun.lock` or `bun.lockb` | `biome` (when `@biomejs/biome` is a dependency), `svelte-check` (when `svelte-check` is a dependency or the `check` script runs it) else `tsc` (when there is a `tsconfig.json` and `typescript` is a dependency), `bun test` (when `package.json` has a `test` script) | `bun install --frozen-lockfile` |
| Python | `pyproject.toml` | `ruff`, `pyright` (pyright-baseline), `pytest` (pytest-baseline) | `uv sync --frozen` (when the root has `uv.lock`) |

Roots are found at the repo root and one level down. Detection applies only when the policy commit has no `tollgate.toml`. `tollgate config --effective` prints the config that jobs use and notes what detection left out; `tollgate config init` writes it to `tollgate.toml` for review.

- **Tools come from the project (R46).** TypeScript tools run from `node_modules/.bin`, Python tools with `uv run --no-sync` after the setup sync. tollgate never downloads a tool (no `bunx`). A missing tool is verdict `error`, cause `setup`, with a message that names it.
- **Linters check the changed files in `fast`.** `biome` and `ruff` lint only the changed files under their root. A change to a file that configures them (`biome.json`, `package.json`, `pyproject.toml`, `ruff.toml`, ...) makes them lint the whole root. Type checkers and test suites always check the whole root, and are skipped when nothing under their root changed (R59, R60).
- **Python baselines (R94).** `pyright-baseline` and `pytest-baseline` follow `pyright-baseline.sh` and `pytest-baseline.sh`, and read the same `.pyright-baseline.json` and `.pytest-baseline.json` files. Only problems that are not in the baseline fail. The baseline comes from the policy commit, never from the branch. Record a baseline at your own terminal (stdin and stdout must be a TTY, and the tree must be clean):

  ```sh
  cd <python root>
  tollgate baseline record pyright    # or: pytest; --force records a dirty tree
  ```

  Commit the file. It applies after it merges to a full ref.
- **Docs-only commits (R61).** A `fast` job passes with zero steps when every changed path is docs-only: a path that matches `select.docs_only`, or a `.md`, `.txt`, image (and similar) file outside every code root that is not under `tests/`, `fixtures/`, `src/`, `prompts/` or `migrations/`. A TypeScript or Python root at the repo root makes every path code, so only `select.docs_only` globs apply there.

## Install

The repo stays local until a GitLab remote is approved (L12).

1. Build and install the binary:

   ```sh
   cargo install --path ~/Repos/tollgate --locked
   ```

2. Arm the gate:

   ```sh
   tollgate install
   ```

   `install` copies the binary to `$XDG_DATA_HOME/tollgate/bin/tollgate`, links the hooks next to it, writes the host config when it is absent, and shows a diff of `~/.claude/settings.json` before it changes it. It asks for confirmation (L10). Agents never run `tollgate install --yes` on the real settings.

   `install.json` records the config, state and data dirs that `install` used. The installed hooks read their dirs from there, not from `HOME` or `XDG_*` in git's environment, so `HOME=/tmp/x git commit` is gated like any other commit (R8). Run `install` from an environment with the same `HOME` and `XDG_*` values as your Claude sessions: the guard reports the gate as not armed when they differ.

3. Check the result:

   ```sh
   tollgate doctor
   ```

   Then, from a Bash call in a Claude session (main session and a subagent), run `tollgate doctor --injection`. Both must report the injection (T1).

4. Edit the host config, `$XDG_CONFIG_HOME/tollgate/config.toml` (R84): `scope` (which repos are gated), `resources` (slot counts), `verify.root` (the disk for verify checkouts). On the Arch box, `verify.root` is `/mnt/devdisk/tollgate/verify`, which needs its `/etc/fstab` line (L5).

Run `tollgate install` again after every `cargo install`: it refreshes the copy and the links (R95). `tollgate uninstall` removes exactly the entries that `install` added (R96). Records, logs and verify checkouts stay until `tollgate gc --all`.

## Daily use

An agent works as before. The gates run by themselves.

| Command | Use |
|---|---|
| `git commit ...` | Runs `pre-commit` (`fast`). On a deny, the report says what failed. |
| `tollgate check [--tier full] [--wait \| --detach]` | Checks the index tree (or `--rev R`, `--tree T`) ahead of a commit or push. |
| `tollgate wait <job>` | Waits for a job: exit 0 pass, 1 fail, 3 still running (L17). |
| `tollgate status [--rev R] [--json]` | Records and running jobs for `HEAD` and the index, the commits on the branch that have no record (L1), and those made without the gate (unverified). |
| `tollgate report <job\|tree>`, `tollgate log <job> <step> [--tail N]` | The full report and a step log (R92). |
| `tollgate cancel <job>` | Stops a queued or running job (R89). |
| `tollgate merge <branch>` | Merges into a full ref with a `full` check before the commit (R99). |
| `tollgate flaky [--days N]`, `tollgate audit [--since D]`, `tollgate gc [--all]` | Flaky test counts, records for review, cleanup. |

When a hook waits longer than its inline budget, it denies and leaves the job running. The deny message gives one command that waits and then retries, for example `tollgate wait <job> && git commit <same args>` (L17).

## CI

`tollgate ci-snippet --gitlab` prints a `.gitlab-ci.yml` job (R73). It runs `tollgate run --tier full --here --report junit`, which runs the setup steps and every step in the CI clone, writes `tollgate-report/report.json` and `tollgate-report/junit.xml` (one test case per step, plus the nextest test suites), and exits non-zero on a failure (R47). On a runner that shares the workstation's test services, the job takes the host resource slots. On hosted runners, add `--no-host-locks`.

## Benchmark (L20)

`tollgate bench` replays commits concurrently from N worktrees of one repo through the real hooks, and reports what the gate costs. Use it to choose the resource slots before a rollout (R98 step 3).

```sh
tollgate bench ~/Repos/myapp --scenarios bench.toml -n 6 --rounds 2 \
  --cpu 3 --pg 2 --pg-max-threads 12 --base-config ~/.config/tollgate/config.toml \
  --scratch /mnt/devdisk/scratch --pg-url postgres://... --out bench.json
```

The scenario file lists the commits. Each scenario gives its worktree count, the file edits before each commit, and how many times to commit the same tree again (`retries`). The worktree counts must add up to N.

```toml
[[scenario]]
name = "core"
worktrees = 2
edit = [{ path = "crates/core/src/lib.rs", append = "\n// bench {worktree}.{round}\n" }]

[[scenario]]
name = "docs"
worktrees = 1
retries = 1
edit = [{ path = "docs/notes.md", write = "# Notes {worktree}.{round}\n" }]
```

An edit appends to a file or writes the whole file. `{worktree}`, `{round}` and `{scenario}` are replaced; other braces stay. Give each worktree and round its own text when each commit must have its own tree. A retry after an allowed commit is `git commit --amend --no-edit` (the same tree: a cache hit); after a deny at the inline budget it is `tollgate wait <job>` and the same commit (L17).

What the bench does:

- It never writes the source repo. It clones it (`git clone --shared --no-checkout`, plus the local branches, which are the policy anchors of L2) into a new scratch dir, and adds one worktree per scenario slot at the source's `HEAD` commit.
- Every git and tollgate process it starts gets its own `XDG_*` dirs in the scratch dir, a host config written from the flags (scope root = the scratch dir), and hooks that are hard links (or copies) of the running binary. A session's hook injection and the installed state are not used.
- A warm-up `tollgate check` of the start commit gives the worktrees a checked base (R56) and step passes to reuse (L16). `--no-warm` skips it.
- Each round, all worktrees edit, then start `git commit` together.
- At the end it cancels the jobs that still run, waits for their runners to exit, kills what is left, and removes the scratch dir (`--keep` keeps it). SIGINT or SIGTERM stops the run early; the cleanup still runs.

The report (text, or JSON with `--json`; `--out FILE` also writes the JSON) gives:

- `pre-commit` latency from hook start to allow (p50, p95, max), from git's own trace2 timing of the hook process, for all commits, cache hits, job runs, docs-only commits, per scenario and per round. The hook's own git calls also write trace events: on a 31 ms cache-hit `pre-commit` this added about 3 ms (2026-11-05), so the numbers are a little high, never low. Chained hooks that run no git are not affected.
- The other hooks' times, the `git commit` wall time, and the denied commits.
- Queue wait per resource (each step's wait for its slots, R85) and for the verify checkout (R87), and the fast job overhead beyond the steps (L19).
- Step reuse (L16), cache hits, the L19 budgets that the run measured, CPU load samples (load average; on Linux also the busy share), and with `--pg-url` the peak client connections of that Postgres (`psql` every `--sample-ms`).

Exit 0 when every commit got a gate decision; 1 when one did not (the repo was out of scope, or there was nothing to commit) or a signal stopped the run; 2 when the bench could not run.

## Limits

### Same-user limitation

tollgate runs as the same user as the agents. Code that runs as one user cannot reliably stop other code that runs as the same user. An agent that wants to bypass tollgate can edit files, kill processes, or write records. tollgate does not protect against a hostile agent. It stops accidental and lazy bypass, and it makes a bypass visible:

- Records are written only by the job runner, and the guard denies writes under the state dir (R83). `tollgate audit` lists records with their duration, log size and tollgate version, so a 0-second pass or an old-version record stands out.
- Your own terminal is not gated (L3). You are the override.
- The last line is GitLab: protect `main` (no direct push, merge through a merge request, pipelines must succeed) and run the CI job on every merge request. A tree that leaves the machine is checked there again.

A branch cannot weaken `tollgate.toml`, nextest config, the Python baselines, or cargo, clippy and rustfmt configs, because they come from the policy commit (L2, R71). Without a `tollgate.toml`, detection (R65) runs on the tree under test and on the policy commit, and every setup and step the policy commit's detection finds stays in the job. So a branch that deletes the `test` script, the `@biomejs/biome` dependency, `tsconfig.json` or a whole root still runs those steps; they fail with a setup error until the change merges to a full ref, and the report names each step that comes only from the policy commit. A branch that adds a root gets that root's steps at once.

The policy commit comes from a trusted remote's `main` (or `master`) only with a value that the trusted server reported: tollgate runs `git ls-remote` against the trusted URL when a remote-tracking ref holds a value it has not seen, so `git fetch .` or `git update-ref` into `refs/remotes/` cannot pick the policy (L2). After a fetch, the first commit asks the server once. When the server cannot be reached and confirms no fetched value, commits are denied until `git fetch` works.

A trusted remote is one whose fetch URL a `scope.remotes` pattern names exactly: `https://`, `ssh://` or `git@host:path`, the exact host, and the path segment by segment, where `*` never crosses `/` (item 34). The same patterns match loosely for scope and push gating, so a look-alike URL (`/tmp/x/gitlab.com/victorkwak/r.git`, `https://evil.example/gitlab.com/victorkwak/r`) is gated but never trusted. A local mirror is trusted only by its exact path in `scope.trusted_paths`.

That query runs in its own environment, so nothing an agent sets for one git command picks who answers: no repo, global or system git config, no `GIT_*` or proxy variable from the shell, and `ssh -o BatchMode=yes` found on `[job] path_prepend` and then `/usr/local/bin:/usr/bin:/bin`, never on the agent's `PATH`. It keeps your `credential.*` git settings and `SSH_AUTH_SOCK`. So an ssh remote needs a key the ssh agent holds (or one without a passphrase) and a known host key, and an https remote needs a credential helper; `http.*` settings such as a proxy or a CA file do not apply. The guard also denies `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_SSH_VARIANT`, `GIT_PROXY_COMMAND` and `GIT_EXEC_PATH` for git and tollgate, and asks before `git config` writes `core.sshCommand`, `core.gitProxy`, `ssh.*` or `url.*`.

A branch can still change its own code, tests, `package.json` scripts, `tsconfig.json`, `biome.json`, and the tool sections of `pyproject.toml`. Those changes are visible in review and in the diff, and the full check at merge runs on them as they are.

### Known gap: commits without a `fast` check (L1)

v1 installs no `reference-transaction` hook. Commits that `cherry-pick`, `revert`, `am` and `rebase` make, and fast-forward merges, get no `fast` check when they are made. They are checked at push (`full`), at `tollgate merge` (`full`), and by `tollgate check`. `tollgate status` shows, for the current branch, the newest commit whose tree has a record and how many commits above it have none.

`git commit --no-verify` and `git merge --no-verify` skip the gate hooks; the guard denies them, and `post-commit` and `post-merge` still detect them. Such a commit stays (nothing is undone), git prints a `tollgate: WARNING`, and `tollgate status` and every later deny list it as unverified until its tree passes a check (`tollgate check --rev <commit>`).

### Other limits

- macOS is not built or tested yet (L13). Every platform-specific call has a macOS branch that is expected to compile.
- That the settings `env` reaches the Bash calls of subagents is not verified (R3). The guard denies every Bash call when the injection is missing, so a gap fails closed.
- A Python root without `uv.lock` gets no `uv sync` setup step: its tools must be on the job `PATH`.
- In a command that names git or tollgate, the guard denies what it does not check instead of decoding it: ANSI-C quoting (`$'...'`), a `\c` escape, and text fed to a shell (or to python or perl) through a pipe, a heredoc, a here-string or an input redirection (item 31). Give a multi-line commit message with `-F <file>` or `-m "$(cat <<'EOF' ... EOF)"`. The guard is still a parser: a command name built from a variable (`${x}t commit`) or arguments that `xargs` reads from a pipe are not seen. A commit made that way without the hooks is marked unverified by `post-commit`, and the push gate and CI check it.

## Migration (R98, adapted to v3)

1. **Arch box, two repos.** Install (see above). Set `scope.include = ["baton", "wikiknit"]` in the host config.
2. **Verify the trigger.** Run the test suite. From a Claude session, run `tollgate doctor --injection` in the main session and in a subagent.
3. **Benchmark (L20).** Run `tollgate bench` (see [Benchmark](#benchmark-l20)) with 6 worktrees of myapp and realistic commits (a core change, an api-only change, a dashboard-only change, a docs change, a retry). Choose `cpu`, `pg` and `pg_max_threads` from that run, not from guesses.
4. **myapp.** Add `myapp*` to `scope.include`. Write `~/Repos/myapp/tollgate.toml`: `select.owners` for `migrations/**`, `select.fast.pg_tests`, the dashboard setup and steps. Add the CI job (`tollgate ci-snippet --gitlab`). Protect `main` on GitLab (Victor).
5. **All repos.** Set `scope.include = ["*"]`.
6. **Mac.** Repeat steps 1-5 on the Mac through the board (L13). Use `only_on = ["macos"]` for iOS steps. Teach `scripts/cargo-guard.sh` the `verify.root` (R44).
7. **Retire the old hook.** `tollgate install` removes the `pre-commit-checks.sh` entry from the settings. Delete the script two weeks after step 5. Keep `.pyright-baseline.json` and `.pytest-baseline.json` in the repos: tollgate reads the same files.

v3 changes to the original plan: there is no `reference-transaction` gate (L1), no `tollgate policy approve` (L2: policy changes apply after they merge), and no `tollgate waive` (L3).

Rollback at any step: run `tollgate uninstall`. It removes the settings entries that `install` added and the installed binary and hooks. It also puts back the PreToolUse entries that `install` removed (the old `pre-commit-checks.sh` hook) when their script still exists, and prints `settings: restored: <command>` for each; do not add them again by hand. When a script is gone, `uninstall` prints `settings: not restored (its script is gone): <command>`; only then copy the entry from the backup that `install` made (`settings.json.tollgate-bak-<timestamp>`, R95) after you restore the script.

## Development

```sh
cargo test
```

Tests use real git repos, real child processes and real tools in temp dirs, with a sandbox `HOME` and XDG dirs. They never touch `~/.claude`, `~/.config` or `~/.local/state`, and they use no network. The TypeScript and Python tests use the `bun`, `uv` and `pyright` on `PATH`, the biome binary in bun's cache, the `tsc` package on `PATH`, and wheels rebuilt from uv's cache. When one of these is missing, the test prints a `SKIP` line and passes.
