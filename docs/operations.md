# Operations

The detailed reference for tollgate: what each gate does, the languages it detects, install and daily use, CI, limits, and the rollout plan. The [README](../README.md) is the short version. The design is [spec.md](spec.md) (v3). Requirement ids (`R<n>`, `L<n>`) in this file point into it. The "Lead decisions" at the top of the spec override the requirements below them.

## Gates and behavior

- **Git hooks, not command text.** `tollgate install` adds `core.hooksPath` to the `env` of `~/.claude/settings.json` (R3). Every `git` process that a Claude session starts (Bash calls, scripts, `bash -c`, `/usr/bin/git`) then runs tollgate's hooks. git aborts the operation when a hook fails or is killed, so the gate fails closed (R37).
- **Four hard gates (L1).**
  - `pre-commit`: tier `fast` on every commit, on every branch (R17).
  - `pre-merge-commit`: the tier of the target branch: `full` for `main`, `master`, `integration/*` (R27, L7).
  - `pre-push`: tier `full` for every branch pushed to a remote whose URL matches `scope.remotes` (trusted or not: a look-alike is gated too), unless `push.fast_refs` matches (R20).
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

1. Build and install the binary:

   ```sh
   cargo install --locked --git https://github.com/victorkwak/tollgate
   # or, from a clone: cargo install --locked --path .
   ```

2. Arm the gate:

   ```sh
   tollgate install
   ```

   `install` copies the binary to `$XDG_DATA_HOME/tollgate/bin/tollgate`, links the hooks next to it, writes the host config when it is absent, and shows a diff of `~/.claude/settings.json` before it changes it. It asks for confirmation (L10). `install` and `uninstall` run only in your own terminal (stdin and stdout are TTYs); there is no `--yes`, and the guard denies both in a Claude session (item 29).

   `install.json` records the config, state and data dirs that `install` used. The installed hooks read their dirs from there, not from `HOME` or `XDG_*` in git's environment, so `HOME=/tmp/x git commit` is gated like any other commit (R8). Run `install` from an environment with the same `HOME` and `XDG_*` values as your Claude sessions: the guard reports the gate as not armed when they differ.

3. Check the result:

   ```sh
   tollgate doctor
   ```

   Then, from a Bash call in a Claude session (main session and a subagent), run `tollgate doctor --injection`. Both must report the injection (T1).

4. Edit the host config, `$XDG_CONFIG_HOME/tollgate/config.toml` (R84): `scope` (which repos are gated), `resources` (slot counts), `verify.root` (the disk for verify checkouts). The file that `install` writes names no repo: `scope.remotes` and `scope.include` are empty, so nothing is gated until you add names, and `verify.root` is unset, so verify checkouts go to the default, `$XDG_STATE_HOME/tollgate/verify`. Set `verify.root` to a fast disk with room for build dirs. The slot counts are the L5 values. `tollgate config --check` validates the file.

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
| `tollgate stats [--since D] [--json]` | What the gate costs: per repo and tier, hook outcomes (cache hits, refusals at the inline cap and the wait until their job ended), job wall and queue p50/p90, step reuse, flaky tests; guard asks and denies by rule. |

When a hook waits longer than its inline budget, it denies and leaves the job running. The deny message gives one command that waits and then retries, for example `tollgate wait <job> && git commit <same args>` (L17).

### Metrics log (item 50)

`tollgate stats` reads `metrics.jsonl` in the state dir. Every guard call, gate hook check, chained hook run and finished job appends one JSON line:

- `guard`: tool, decision (`allow`, `ask`, `deny`), rule id, R28 rewrite, the guard's own time in µs, and, for an ask or deny, a keyed BLAKE3 hash of the command or file path (16 hex digits). The log never holds the text. The key is `metrics.key` (0600); share the log without it. With no usable key the hash is left out.
- `hook`: one line per check: hook, repo, tier, outcome (`cache_hit`, `passed`, `remote_verified`, `refused_cap`, `failed`, `error`), job id, the hook's time to its decision (`ms`, from the start of the hook process: config, scope and remote loading and the staged-tree work are in it, so it compares with the L19 budgets and `tollgate bench`), the repo's own hook's share of it when the repo has one (`repo_hook_ms`), and a run id that the checks of one hook run share. `hook p50/p90` is `ms` without `repo_hook_ms`, tollgate's own time; it takes one sample per hook run in each row, so a push of five refs counts as one wait, not five; the outcome counts stay per check. Lines from before the run id group by their shared time.
- `chained`: one line per chained (non-gate) hook run that exits 0: hook, repo, the hook's time in µs from the start of the hook process (`us`, L19 budget 5 ms), the repo hook's share (`repo_hook_us`), and the exit it took. `chain` is a hook that only chains to the repo hook. `post-commit` and `post-merge` (item 17) take a cheap exit of item 37 (`marker`: a gate hook of the same git command allowed the commit; `squash`; `sequencer`; `fast_forward`; `tree_passed`: one `rev-parse`) or the full check after loading the host config, scope and remotes (`full`, or `recorded` when it recorded an unverified commit). The `chained hooks` table shows runs, tollgate's own time p50/p90 (without the repo hook) and the runs by exit, per hook.
- `job`: repo, tier, `hook` or `prewarm`, verdict, wall time, queue time before the first step and in step slots, checkout wait, steps and steps reused, flaky and quarantined tests.

The file is 0600 and append-only. Past 8 MiB it rotates to `metrics.jsonl.1` (3 kept, 32 MiB at most). A write error, a planted symlink or FIFO, or a panic in the logger is dropped: the log never changes a guard answer or a hook verdict. Cost on the guard path (release build, 2026-11-09): the append takes about 15-30 µs inside the process (serialize about 9 µs, open, write, close), and the hash on an ask or deny about 25 µs more; an allow carries no hash. The same binary with the log switched off at run time was within ±15 µs of it at p50 over 400 interleaved runs (guard process p50 1.1-1.9 ms), so the cost does not show at process level.

In the hook table, `retry` counts allows that ended a commit refused at the inline cap: the first check after a `refused_cap` with the same job id that allowed (the `tollgate wait <job> && git commit` retry, or a retry that joined the still running job). Such a check saved no time, so it is not in `checks`, `hit` or `inline`; a retry that denies stays a check and a failure. With `--since` after the refusal, its retry counts as a hit. A refusal is `open` while its job has no `job` line: the job still runs, or its line was rotated out. A job whose runner died gets its line, verdict `lost`, from the reap (`tollgate wait`, `tollgate cancel`, `gc`, or the next job of the same key); it counts as a job that did not pass, without wall or queue time. A refusal of a lost job is closed and counts as `lost` in the `cap` column, but not in `cap->end`: the lost line's time is the reap, which can come hours after the runner died. A job that ended between the inline cap and the hook's time stamp counts a wait of 0.

Use the rule table for false-deny review: a rule with many denies over few distinct commands means agents retried the same command; many distinct commands means the rule fires often.

## CI

`tollgate ci-snippet --gitlab` prints a `.gitlab-ci.yml` job (R73). It runs `tollgate run --tier full --here --report junit`, which runs the setup steps and every step in the CI clone, writes `tollgate-report/report.json` and `tollgate-report/junit.xml` (one test case per step, plus the nextest test suites), and exits non-zero on a failure (R47). On a runner that shares the workstation's test services, the job takes the host resource slots. On hosted runners, add `--no-host-locks`.

## Limits

### Same-user limitation

tollgate runs as the same user as the agents. Code that runs as one user cannot reliably stop other code that runs as the same user. An agent that wants to bypass tollgate can edit files, kill processes, or write records. tollgate does not protect against a hostile agent. It stops accidental and lazy bypass, and it makes a bypass visible:

- Records are written only by the job runner, and the guard denies writes under the state dir (R83). `tollgate audit` lists records with their duration, log size and tollgate version, so a 0-second pass or an old-version record stands out.
- Your own terminal is not gated (L3). You are the override.
- The last line is GitLab: protect `main` (no direct push, merge through a merge request, pipelines must succeed) and run the CI job on every merge request. A tree that leaves the machine is checked there again.

A branch cannot weaken `tollgate.toml`, nextest config, the Python baselines, or cargo, clippy and rustfmt configs, because they come from the policy commit (L2, R71). Without a `tollgate.toml`, detection (R65) runs on the tree under test and on the policy commit, and every setup and step the policy commit's detection finds stays in the job. So a branch that deletes the `test` script, the `@biomejs/biome` dependency, `tsconfig.json` or a whole root still runs those steps; they fail with a setup error until the change merges to a full ref, and the report names each step that comes only from the policy commit. A branch that adds a root gets that root's steps at once.

The policy commit comes from a trusted remote's `main` (or `master`) only with a value that the trusted server reported: tollgate runs `git ls-remote` against the trusted URL when a remote-tracking ref holds a value it has not seen, so `git fetch .` or `git update-ref` into `refs/remotes/` cannot pick the policy (L2). After a fetch, the first commit asks the server once. When the server cannot be reached and confirms no fetched value, commits are denied until `git fetch` works.

A trusted remote is one whose fetch URL a `scope.remotes` pattern names exactly: `https://`, `ssh://` or `git@host:path`, the exact host, and the path segment by segment, where `*` never crosses `/` (item 34). The same patterns match loosely for scope and push gating, so a look-alike URL (`/tmp/x/gitlab.com/you/r.git`, `https://evil.example/gitlab.com/you/r`) is gated but never trusted. A local mirror is trusted only by its exact path in `scope.trusted_paths`, and only when that path and the remote URL are canonical: no symlink part, `..` or trailing `/` (item 48). `tollgate doctor` names the canonical path to use.

Once a repo had a trusted remote, tollgate remembers it (item 33). If that remote is later removed, renamed to another URL, or no longer trusted by `scope.remotes`, commits and pushes in the repo are denied with a message that names it, instead of taking the policy from the local `main`, which anything in the repo can move. Put the remote back (`git remote add` or `git remote set-url` with the URL in the message), or accept the change from your own terminal:

```sh
cd <repo>
tollgate remotes forget    # lists what is recorded, asks [y/N]
```

This memory follows the repo's history, not its path: a copy (`cp -a`), a move, or a clone of the repo that has none of its trusted remotes is denied the same way, and the message names the repo where the remote was recorded. So a local clone of a gated repo whose `origin` is that local path is denied at its first gated commit until you run `tollgate remotes forget` in it once (or add a trusted remote). Forgetting is remembered: that clone does not take the accepted remotes over again.

`tollgate install` also writes `~/.local/state/tollgate/trusted-remotes/index.json`, the list of every repo that had a trusted remote. If that file is deleted, commits and pushes are denied in every repo, in scope or not, that has no complete record of its own (a repo whose record holds its current trusted remotes does not need the list), because a repo whose record was deleted with it would look new. A later `tollgate install` does not write it again (it says so and exits non-zero). `tollgate remotes forget` in any repo writes a new one from the records that are still there; repos whose record was deleted lose their memory.

That query runs in its own environment, so nothing an agent sets for one git command picks who answers: no repo, global or system git config, no `GIT_*` or proxy variable from the shell, and `ssh -o BatchMode=yes` found on `[job] path_prepend` and then `/usr/local/bin:/usr/bin:/bin`, never on the agent's `PATH`. It keeps your `credential.*` git settings and `SSH_AUTH_SOCK`. So an ssh remote needs a key the ssh agent holds (or one without a passphrase) and a known host key, and an https remote needs a credential helper; `http.*` settings such as a proxy or a CA file do not apply. The guard also denies `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_SSH_VARIANT`, `GIT_PROXY_COMMAND` and `GIT_EXEC_PATH` for git and tollgate, and asks before `git config` writes `core.sshCommand`, `core.gitProxy`, `ssh.*` or `url.*`.

A branch can still change its own code, tests, `package.json` scripts, `tsconfig.json`, `biome.json`, and the tool sections of `pyproject.toml`. Those changes are visible in review and in the diff, and the full check at merge runs on them as they are.

### Known gap: commits without a `fast` check (L1)

v1 installs no `reference-transaction` hook. Commits that `cherry-pick`, `revert`, `am` and `rebase` make, and fast-forward merges, get no `fast` check when they are made. They are checked at push (`full`), at `tollgate merge` (`full`), and by `tollgate check`. `tollgate status` shows, for the current branch, the newest commit whose tree has a record and how many commits above it have none.

`git commit --no-verify` and `git merge --no-verify` skip the gate hooks; the guard denies them, and `post-commit` and `post-merge` still detect them. Such a commit stays (nothing is undone), git prints a `tollgate: WARNING`, and `tollgate status` and every later deny list it as unverified until its tree passes a check (`tollgate check --rev <commit>`).

### Other limits

- macOS (L13) builds and passes its tests except `a_dead_runner_leaves_no_step_and_no_free_slot_behind_r35_r85` and `waiting_on_a_dead_runner_reaps_its_steps_r35`. It has no parent-death signal, so a step outlives a SIGKILLed runner, and `KERN_PROCARGS2` shows an unprivileged caller no environment, so `reap_if_lost` cannot find the lost job's processes by their `TMPDIR` entry. Those processes keep their resource slots until they exit. Also on macOS: no subreaper, so a process a step had already orphaned is out of the walk, and `doctor` only warns about an old git lock, because it cannot tell whether a live git owns it (R39).
- The settings `env` reaches the Bash calls of subagents (R3; checked with Claude Code 2.1.317). The guard denies every Bash call when the injection is missing, so a gap in another version fails closed.
- A Python root without `uv.lock` gets no `uv sync` setup step: its tools must be on the job `PATH`.
- In a command that names git or tollgate, the guard denies what it does not check instead of decoding it: ANSI-C quoting (`$'...'`), a `\c` escape, and text fed to a shell (or to python or perl) through a pipe, a heredoc, a here-string or an input redirection (item 31). Give a multi-line commit message with `-F <file>` or `-m "$(cat <<'EOF' ... EOF)"`. The guard is still a parser: a command name built from a variable (`${x}t commit`) or arguments that `xargs` reads from a pipe are not seen. A commit made that way without the hooks is marked unverified by `post-commit`, and the push gate and CI check it.

## Rollout

The rollout plan of R98, adapted to v3. It is written for the author's machines; the order applies to any setup.

1. **One machine, two small repos.** Install (see above). Set `scope.include` to two repos in the host config.
2. **Verify the trigger.** Run the test suite. From a Claude session, run `tollgate doctor --injection` in the main session and in a subagent.
3. **Benchmark (L20).** Run `tollgate bench` (see [benchmark.md](benchmark.md)) with 6 worktrees of myapp and realistic commits (a core change, an api-only change, a dashboard-only change, a docs change, a retry). Choose `cpu`, `pg` and `pg_max_threads` from that run, not from guesses.
4. **myapp.** Add `myapp*` to `scope.include`. Write `~/Repos/myapp/tollgate.toml`: `select.owners` for `migrations/**`, `select.fast.pg_tests`, the dashboard setup and steps. Add the CI job (`tollgate ci-snippet --gitlab`). Protect `main` on the remote.
5. **All repos.** Set `scope.include = ["*"]`.
6. **Mac.** Repeat steps 1-5 on a Mac (L13). Use `only_on = ["macos"]` for iOS steps. When the Mac runs its own cargo guard script, teach it the `verify.root` (R44).
7. **Retire the old hook.** `tollgate install` removes a PreToolUse entry for `pre-commit-checks.sh` (the commit-check script tollgate replaces), when the settings have one. Delete the script two weeks after step 5. Keep `.pyright-baseline.json` and `.pytest-baseline.json` in the repos: tollgate reads the same files.

v3 changes to the original plan: there is no `reference-transaction` gate (L1), no `tollgate policy approve` (L2: policy changes apply after they merge), and no `tollgate waive` (L3).

Rollback at any step: run `tollgate uninstall`. It removes the settings entries that `install` added and the installed binary and hooks. It also puts back the PreToolUse entries that `install` removed (the old `pre-commit-checks.sh` hook) when their script still exists, and prints `settings: restored: <command>` for each; do not add them again by hand. When a script is gone, `uninstall` prints `settings: not restored (its script is gone): <command>`; only then copy the entry from the backup that `install` made (`settings.json.tollgate-bak-<timestamp>`, R95) after you restore the script.

## Development

```sh
cargo test
```

Tests use real git repos, real child processes and real tools in temp dirs, with a sandbox `HOME` and XDG dirs. They never touch `~/.claude`, `~/.config` or `~/.local/state`, and they use no network. The TypeScript and Python tests use the `bun`, `uv` and `pyright` on `PATH`, the biome binary in bun's cache, the `tsc` package on `PATH`, and wheels rebuilt from uv's cache. When one of these is missing, the test prints a `SKIP` line and passes.
