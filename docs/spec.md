# tollgate: design specification (v3)

v3 = the architect's draft 2 (below, from "# tollgate: design specification") plus the lead decisions in this section. Where a lead decision and a requirement disagree, the lead decision wins. Requirement numbers are kept so tests can cite them; requirements marked CUT below are not built in v1.

## Lead decisions (v3, 2026-11-05)

L1. **No `reference-transaction` gate in v1.** CUT: R9, R10, R11, R12 (except `GIT_NO_REPLACE_OBJECTS=1` on every tollgate git call, which stays), R13, R14 outcome (2) stays only for `pre-merge-commit`/`pre-push` lookups, R16, R18, R19, R21, R29 (ledger), R30 (tamper report), T6-T12, T44, and the `procs` parent-command lookup. `reference-transaction` is not installed.
Hard gates are: `pre-commit` (fast), `pre-merge-commit` (tier by target ref), `pre-push` (full to trusted remotes, R20), and CI with GitLab protection of `main`.
Reason: a `reference-transaction` gate fires on checkout, fetch, pull, reset and rebase (about 1300 calls for a 60-commit rebase) and must tell legitimate moves from unchecked ones with reachability, reflog and marker heuristics. Each heuristic is a false-deny risk for every agent and a false-allow risk, and it adds no protection beyond the push gate and CI, which see every tree that leaves the machine.
Known gap, documented in the README: commits made by `cherry-pick`, `revert`, `am`, `rebase`, and fast-forward merges get no `fast` check when they are made. They are checked at push (full), at `tollgate merge` (full), and by `tollgate check`. `tollgate status` must show, for the current branch, the newest commit whose tree has a record and how many commits above it have none. v2 candidate.
Note (unverified commits, item 17, detection only): `--no-verify` skips `pre-commit` and `pre-merge-commit`, but `post-commit` and `post-merge` still run. A gate hook that allows its commit leaves a marker named by its parent git process (pid and start time) in `$XDG_STATE_HOME/tollgate/gate-runs/`; the post hook of the same git process takes it, with no subprocess (L19). Without a marker, outside a sequencer operation (`CHERRY_PICK_HEAD`, `REVERT_HEAD`, `rebase-*`, `sequencer`, or, on Linux, a parent git running `cherry-pick`, `revert`, `rebase` or `am`), in an in-scope repo, a `HEAD` whose tree never passed a job or a gate hook and that no trusted remote-tracking ref contains is recorded in `unverified/<repo key>.json` with a warning. The record names the git command as `git <subcommand>` plus the flag names `--no-verify`, `-n`, `--amend`, `--no-ff`, `-a` that it used, never a value: `-c`/`--config-env` contents, URLs and messages can hold secrets (item 30). Cheap checks come first (item 37, L19): a `post-merge` whose new `HEAD` is the tip of another ref (a fast-forward, which makes no commit; read from the git dir files, no subprocess) and a `HEAD` whose tree passed (one `rev-parse`) record nothing, and only then are the host config, scope and remotes loaded. `tollgate status` lists those on the branch whose tree has not passed since, and every deny names them. Nothing is undone: a `reset` from a hook could lose work, and push, merge and CI still check every tree. On macOS a revert is flagged too (the parent's command line is not read, L13).

L2. **Policy base without an approval flow.** Policy commit = `git merge-base N <anchor>` where anchor is the first that exists of: the trusted remote's full refs (`refs/remotes/<trusted>/main`, ...), the local full refs; with no anchor, `N` itself. Policy files (R71) come from that commit (R49 stays). CUT: R66 candidate/approval logic, R67 union rule, R68 `policy approve`, Q15. A branch's own policy changes take effect after it merges to a full ref. Every report on a tree whose policy files differ from the policy commit prints one line: `POLICY: this branch changes <files>; checks use the policy of <commit> until it merges to <ref>`. R64 and R69 (quarantine `until` at most 30 days after the policy commit's committer date) stay.
Reason: the approval flow and union rule are complex and still leave CI on the tree's own policy. Reading policy only from a protected merge-base is exact and stops a branch from weakening its own checks.
Note (anchor provenance, X1): a remote-tracking ref is a local file. `git update-ref`, `git fetch . x:refs/remotes/origin/main` and `git fetch <path> ...` write it, and they can write a fetch-like reflog line, so neither the ref nor its reflog proves where its value came from. A remote-tracking anchor (and an R56 trusted base) counts only with a value the trusted server reported: `git ls-remote --heads` against the remote's fetch URL as git uses it, run with no repo (`GIT_DIR=/dev/null`) and no global or system config (`GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`), so neither repo nor user config (`remote.<n>.uploadpack`, `core.sshCommand`, `url.*`) can change who answers. The query has its own environment, not the hook's: `PATH` is `job.path_prepend` then `/usr/local/bin:/usr/bin:/bin`, `HOME` is tollgate's home, ssh is `ssh -o BatchMode=yes`, and from the hook's environment it keeps only what reaches credentials (`SSH_AUTH_SOCK`, `USER`, `LOGNAME`, `XDG_RUNTIME_DIR`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`) plus the user's `credential.*` settings (a helper supplies credentials; it cannot change the server). So `GIT_SSH_COMMAND`, `GIT_SSH`, `GIT_EXEC_PATH`, a fake `ssh` first on the agent's `PATH`, or a proxy variable set for one git command cannot answer for the trusted server either (review R1). Other `http.*` settings (proxy, CA file) do not reach the query. Answers are kept in `$XDG_STATE_HOME/tollgate/remote-refs.json` (the newest 16 values per branch). The anchor commit is the newest reported value of the branch that the repo has, never an older one the tracking ref was moved back to. The server is asked when the tracking ref holds a value it never reported (after a fetch, or a forgery), or a reported but older value and the last answer is more than 10 minutes old. When the server confirms no value that the repo has (unreachable, or not fetched), the anchor is unusable; with no usable remote anchor left, the policy denies and names `git fetch <remote>`. R14(2) asks the same way.
Note (second pass): when the anchor commit's `policy.anchors` names other branches and none of them exists, the first pass stays; it never falls back to `N` itself. The same holds with a trusted remote, when none of `refs/remotes/<trusted>/<name>` exists (item 32); named refs that exist but whose value the server does not confirm still deny.
Note (`rust-toolchain`, item 4, declined): `rust-toolchain` and `rust-toolchain.toml` are not policy files. Reason: a branch that bumps the toolchain on purpose would run its own checks on the old toolchain until it merges, and fail them for a reason that is not in its code. The toolchain each Rust root resolves is in the fingerprint (`rustc -vV`, `cargo -V` run in a probe dir that holds the tree's toolchain files, R74), so a record never answers for another toolchain, and choosing an older toolchain does not weaken any check that `tollgate.toml` defines. A toolchain file that names a toolchain dir (`path`) is refused, so the probe runs no tool the tree chooses (R51). Item 28: only an allowlist is read: a `[toolchain]` table and nothing else, whose keys are `channel` and `profile` (plain names, `[A-Za-z0-9._-]`) and `components` and `targets` (lists of plain names), or, in `rust-toolchain` only, one line holding a channel name. Any other shape (not UTF-8, other keys, several lines of non-TOML) is refused with its reason.

L3. **No `tollgate waive`.** CUT: R100, R113, Q6. Victor's terminal is not gated: he is the override.

L4. **Scope.** A repo is in scope when a remote URL matches `scope.remotes`, or when the realpath of the parent of its common dir is a direct child of a `scope.roots` entry (depth exactly 1), and `scope.include`/`exclude` allow its basename. Linked worktrees of an in-scope repo are in scope wherever they live (their common dir decides). Nested repos (test fixtures under `target/`, `node_modules/`, temp dirs) are out of scope.
Reason: tests create git repos inside in-scope checkouts; depth 1 keeps them out without a list of directory names.

L5. **Host defaults for the Arch box.** `verify.root = "/mnt/devdisk/tollgate/verify"` (SSD; not `/mnt/data1`, a spinning mergerfs member). `verify.slots = { fast = 3, full = 2 }`. Resources `cpu = 3`, `pg = 2`, `pg_max_threads = 12` (the test Postgres runs with `max_connections = 500`; myapp tests open 6 connections each). Q5 resolved, except that `/mnt/devdisk` still needs an `/etc/fstab` line (Victor).

L6. **Selection without guppy.** Use `cargo_metadata` only. Compute the reverse-dependency closure, including dev-dependency edges, from the resolve graph. Fast test mode default `rdeps-all` (Q3). Reason: one dependency less; the closure is a few lines; `rdeps-all` errs toward running more.

L7. `tiers.full_refs` default `["main", "master", "integration/*"]` (Q1). Pushes to trusted remotes need `full` for every branch; `push.fast_refs` default `[]` (Q2).

L8. **Guard when unarmed.** R24 stays (deny every Bash call when the injection, hooks dir or links are wrong), except a command whose first word is the tollgate binary (PATH name or installed copy) with subcommand `install`, `uninstall`, `doctor`, `status`, which is allowed so the state can be repaired from a session (Q14).

L9. Python: `pytest-baseline` runs in `fast` too (Q10). Flaky policy as R93 with `retries = 2` (Q4). Tags not gated (Q7).

L10. `tollgate install` never edits `~/.claude/settings.json` without an interactive confirmation; `--yes` is for tests: when stdin is not a TTY it is refused for the account's real settings, any file under `<passwd home>/.claude/` after symlinks of the file and its dirs are resolved (the passwd home, which no variable changes). Tests use a sandbox settings file. Agents never run `install --yes` on the real settings.
Note (item 9): the first version allowed a TTY-less `--yes` with `TOLLGATE_TEST_INSTALL=1` and the settings under `$TMPDIR`; `TMPDIR=~/.claude` passed that check. No variable takes part now. A pty (`script -c ...`) still gives stdin a TTY: that is a guard matter.

L11. `~/.claude/settings.json` is per machine (not synced): Q11 resolved, no machine-neutral path needed.

L12. The repo stays local (`~/Repos/tollgate`) until Victor approves a GitLab remote (Q12). Q13 (protect `main` on GitLab) is Victor's.

L13. macOS: build and unit-test on the Mac later through the board; Linux first. Keep every platform-specific call behind `cfg(target_os)` with a macOS implementation that compiles.

L14. CLI subset for v1: `install`, `uninstall`, `doctor`, `check`, `wait`, `cancel`, `status`, `report`, `log`, `run --here`, `merge`, `config --effective|--check|init`, `ci-snippet --gitlab`, `baseline record`, `flaky`, `audit`, `gc`, `guard`, `hook`. CUT: `pick`, `policy approve`, `waive`.


## Performance and autonomy decisions (v3.1, 2026-11-05)

Victor: agents as autonomous as practical without giving up safety or quality; 2026-11-04 showed what slow, rerun-from-zero gates cost. These decisions are binding for the Runner, Hooks and later phases.

L15. **Sticky verify checkouts.** A fast verify checkout is keyed by origin (the agent worktree path that started the job, from the hook's repo toplevel), not taken from a shared pool: each agent worktree gets its own `fast` checkout with its own target dir, created on first use, so its incremental build stays warm and it never rebuilds another branch's tree. `verify.max_checkouts` (default 12 per repo) with LRU eviction (`cargo clean` is not needed: the whole checkout is removed). Full checkouts: keyed the same way, `verify.max_full_checkouts` default 4, LRU. Concurrency is limited by resource slots (R85), not by checkout count. `verify.slots` (R41) is CUT.
Reason: a shared checkout that alternates between diverged branches recompiles most of the workspace on each switch (minutes for myapp), which would recreate the 2026-11-04 slowness.

L16. **Step-level reuse by inputs.** A step may declare `inputs` (globs, default `["**"]`) and `exclude_inputs` in policy (from the policy commit, L2). The step's result is stored under a step key = blake3(step definition, fingerprint, sorted list of (path, blob oid, mode) of the tree entries matching its inputs). A job reuses a stored `pass` for a step whose step key matches, and reports it as `REUSED <step> from <job>`. Reuse applies to `fast` jobs and to pushes of non-full refs. `full` jobs for full refs (`tollgate merge`, pushes to `main`) and CI run every step fresh: no reuse there.
Reason: in myapp an iOS-only or dashboard-only change must not rerun the Rust suite on every commit. A wrong `exclude_inputs` can delay detection only until the merge to a full ref, which always runs everything.

L17. **Long checks without retry loops.** The guard (R28) sets `TOLLGATE_INLINE_CAP` to the `fast` budget (default 20 min) when the Bash call has `run_in_background: true`, and to 540 s otherwise. The deny message after the inline budget gives one command that waits and then commits: `tollgate wait <job> && git commit <same args>` (tollgate prints the exact command, with the original arguments, from the hook's view of argv where git exposes it, else a placeholder). `tollgate wait` exits 0 on pass, 1 on fail (and prints the report), 3 on still running after its timeout.

L18. **Self-repair before deny.** When the guard's self-check (R24) finds a missing or dangling hook link or a missing hooks dir, and `install.json` and the installed binary copy are intact, the guard recreates the links (same inode checks after) and allows the call, writing one line to `$XDG_STATE_HOME/tollgate/repairs.log`. It denies only when repair fails or the settings env is wrong (settings are never edited by the guard).

L19. **Performance budgets** (p95 on the Arch box, tested where marked):
- Guard per call: under 10 ms (test: 200 calls).
- Chained non-gate hook (for example `post-commit` with no repo hook): under 5 ms (test).
- `pre-commit` on a cache hit: under 200 ms (test).
- `pre-commit` on a docs-only tree: under 200 ms (test). Item 41: a hook waiting for a job looks at it after 1 ms, then at doubling pauses up to 100 ms, so a job of a few ms answers near its run time; the test asserts 90 ms (120 ms with detected Bun and Python roots), the measured p95 plus a margin.
- Fast job overhead beyond the steps themselves (checkout update, metadata, selection, record write): under 3 s for a myapp-sized workspace (bench).
- No tollgate code on the path of git commands that run no hooks (`status`, `diff`, `log`, `show`, `fetch`).

L20. **Benchmark before rollout.** `tollgate bench` (dev command, or `benches/` harness) replays commits concurrently from N worktrees of one repo through the real hooks and reports p50/p95 commit latency (hook start to allow), queue wait per resource, CPU load, peak test-Postgres connections, cache hits and step reuse. Rollout to myapp (R98 step 3) needs a run with 6 worktrees and realistic commits (a core change, an api-only change, a dashboard-only change, a docs change, a retry) and resource slot values (`cpu`, `pg`, `pg_max_threads`) chosen from that run, not guessed. L5's slot numbers are starting values only.
Note (built, 2026-11-05): `tollgate bench <repo> --scenarios <file> [-n N]` (README "Benchmark"). The source repo is never written: the bench clones it (`--shared`, plus its local branches as L2 anchors) into a new scratch dir and makes N worktrees there; its git and tollgate processes get their own `XDG_*` dirs, a host config from the flags (scope root = the scratch dir) and hooks linked from the running binary, so neither a session's injection nor the installed state takes part (R8). Hook latency is git's trace2 time of the hook process. Queue wait per resource comes from the job reports (`steps[].resources`, `steps[].queue_ms`, `checkout_wait_ms`). Cleanup cancels running jobs, waits for their runners, kills what is left (Linux: by the state dir in the environment) and removes the scratch dir.

---

# tollgate: design specification

Status: draft 2, 2026-11-05. Author: architect agent. Owner: Victor.
Working repo: `~/Repos/tollgate` (Rust, `cargo install` on the Arch box and the Mac).

Writing style: ASD-STE100. Requirements are numbered `R<n>` so tests can cite them. Requirement numbers changed from draft 1; Appendix A maps the critique's old numbers to the new ones. Each decision has a `Reason:` line. Items the research did not verify are marked `UNVERIFIED` and the safer design is chosen.

---

## 1. Purpose

tollgate gates the ref updates that a Claude Code session makes in a git repo. It runs the repo's checks on the exact tree that becomes a branch tip, records the result by tree hash, and refuses the update when the checks did not pass. It replaces `~/.claude/hooks/pre-commit-checks.sh`.

| # | Problem today | tollgate answer |
|---|---|---|
| 1 | PreToolUse timeout fails open | Enforcement is a git hook. git aborts the operation when the hook exits non-zero or is killed (verified). A text guard with `onFailure: block` covers what hooks cannot see. |
| 2 | Full suite on every commit | Two tiers. `fast` on every commit (affected packages only). `full` at handoff (push), at merge into a full ref, and in CI. |
| 3 | Checks the working tree | Checks `git write-tree` of the hook's index, in a private verify checkout with a clean environment. Dirty and untracked files never take part. |
| 4 | No memory | Results keyed by tree hash, tier, fingerprint and (for `fast`) the selection that ran. Identical trees are never re-checked. |
| 5 | Regex trigger | Hook injection through git config env. Catches `bash -c`, scripts, cherry-pick, rebase, merge, am, reset, push, `/usr/bin/git`. The guard is a backstop for env loss and config overrides. |
| 6 | Checks not owned by the repo | `tollgate.toml` in the repo, read from a trusted base commit. CI runs `tollgate run --tier full --here` from the same file. |
| 7 | Last 40 lines | Structured report: failing step, failing test names, rerun command, `tollgate log` for the full log. |
| 8 | No shared-resource control | Host-wide slot locks (`cpu`, `pg`, ...) with `flock(2)`, portable to macOS. CI jobs on the workstation take the same slots. |
| 9 | Flaky blocks everyone | nextest retries. Flaky tests pass `fast` with a loud report, fail `full` unless quarantined with an expiry. |

Non-goals: gating Victor's own terminal (CI covers it). Protecting against a hostile agent: same-user code cannot be stopped by same-user code. tollgate stops accidental and lazy bypass, makes every bypass visible, and relies on GitLab branch protection for `main` as the last line (R34, R111).

---

## 2. Terms

- **Tree**: a git tree object id. The content of a commit, with no message or parents.
- **Record**: the stored result of one tier on one tree under one fingerprint. Verdict: `pass`, `fail`, `timeout`, `error`.
- **Tier**: `fast` or `full`. A `full` pass implies `fast`.
- **Full ref**: a branch whose name matches `tiers.full_refs` (default `main`, `master`). Case-insensitive match (R27).
- **Trusted remote**: a remote whose URL matches `scope.remotes` in the host config (the GitLab projects). Its `refs/remotes/<r>/*` are trusted because GitLab protects `main` and CI runs there.
- **Base**: the tree a change is compared with for selection (R62) and the commit whose policy files apply (R71).
- **Policy files**: `tollgate.toml`, `.config/nextest.toml`, `.pyright-baseline.json`, `.pytest-baseline.json`, plus `policy.files` globs.
- **Gate hook**: `pre-commit`, `pre-merge-commit`, `pre-push`, `reference-transaction`.
- **Verify checkout**: a private, persistent, locked git worktree per repo clone and tier where checks run.
- **Job**: one run of one tier on one tree. A detached process. Hooks wait on jobs.
- **Inline budget**: how long a hook waits for a job before it denies.
- **Guard**: the Claude Code PreToolUse hook `tollgate guard`. Text and environment backstop.
- **Ledger**: per-repo state tollgate keeps: last allowed tip per full ref, pending commit markers, pending sequences, approved policy sets.

---

## 3. Architecture

```
Claude Code session (settings.json env: GIT_CONFIG_* -> core.hooksPath = <hooks dir>)
   |
   | any `git` process (Bash tool, subagent, script, bash -c, /usr/bin/git)
   v
git ---- runs hook ----> <hooks dir>/<hook name>   (hard link to the installed tollgate copy)
                              |
                              |-- not a gate hook: chain to the repo's own hook, exit
                              |-- gate hook: decide (R17-R30) -> tree T, tier, base
                                    |-- record hit (R78-R83)            -> allow
                                    |-- record fail                     -> deny + stored report
                                    |-- no record -> job start or attach; wait <= inline budget
                                          |-- pass -> allow ; else deny, job continues detached
   |
   +-- PreToolUse Bash / Write|Edit: tollgate guard  (env self-check, text patterns, 10 s, onFailure=block)

job runner (detached, own session, clean env):
   scheduler slot -> verify checkout lock -> read-tree + clean -> setup steps
   -> for each step: resources (canonical order) -> run in own process group -> log
   -> parse results -> write record (atomic rename) -> release
```

Decision D1: the primary trigger is git's own hook mechanism, injected into Claude processes through environment. Not a PATH shim, not command-text parsing.
Reason: env injection reaches every git process in the Claude process tree including `/usr/bin/git` and scripts (verified). git aborts on hook failure or hook kill (verified), so the gate is fail closed without Claude Code cooperation.

Decision D2: no hook manager (lefthook, hk, prek, pre-commit) as the engine.
Reason: none caches by tree hash, none checks the exact index tree without mutating the live checkout, none has cross-process resource limits, and all expose bypass flags to the committer (verified).

Decision D3: tollgate shells out to the `git` binary. No libgit2, no gix.
Reason: same semantics as the git that runs the hook (worktrees, index file, config). Every tollgate git call runs with `GIT_NO_REPLACE_OBJECTS=1` and a scrubbed environment (R52).
Note (item 39): git puts `GIT_EXEC_PATH` first on its hooks' `PATH`, so `git` looked up on `PATH` could be any binary the caller chose. tollgate runs git by an absolute path that `install` fixes (the first `git` in `[job] path_prepend`, then `/usr/local/bin`, `/usr/bin`, `/bin`, never the caller's `PATH`) and records in `install.json`; hooks, runners and the CLI read it from the install they belong to, `doctor` checks that it runs. Without a record (a dev build) the same system dirs decide. `GIT_EXEC_PATH` is removed from every git tollgate starts and from the runner's environment.

Decision D4: the hard gate for full refs is `pre-push` to a trusted remote plus GitLab branch protection. Local full-ref tips are gated too, but local bypasses that git does not show to hooks (branch rename, reftable) are detected and reported, not prevented.
Reason: git branch rename does not show the new value to `reference-transaction` and runs no hook on reftable (verified). What leaves the machine is what matters: push and merge are gated by tree record.

Decision D5: policy is read from a trusted base commit, not from the tree under test.
Reason: a commit must not be able to weaken the checks that judge it (critique). Content-addressed policy from the base is exact and cheap.

Decision D6: jobs run with a built environment, never the hook's inherited one.
Reason: hooks inherit `GIT_INDEX_FILE`, `GIT_DIR` and the injection (verified); inherited values corrupt the agent's index and gate test repos recursively.

---

## 4. Requirements

### 4.1 Installation of the trigger, scope, chaining

R1. `tollgate install` must copy the running binary to `$XDG_DATA_HOME/tollgate/bin/tollgate` (default `~/.local/share/tollgate/bin/tollgate`; same layout on macOS) and must create `$XDG_DATA_HOME/tollgate/hooks/<name>` as a hard link to that copy for each name in R2. tollgate must dispatch on the basename of `argv[0]`.
Reason: a symlink to `~/.cargo/bin/tollgate` dangles after `cargo uninstall` or a move, and git runs a commit with no hooks and no message when a hook file or the hooks path is missing (verified). A private copy cannot disappear with the PATH binary. Hard links give argv[0] dispatch with no shell startup.

R2. Installed hook names: gate hooks `pre-commit`, `pre-merge-commit`, `pre-push`, `reference-transaction`; chained hooks `applypatch-msg`, `pre-applypatch`, `post-applypatch`, `prepare-commit-msg`, `commit-msg`, `post-commit`, `pre-rebase`, `post-checkout`, `post-merge`, `post-rewrite`, `pre-auto-gc`. Not installed: `post-index-change`, `push-to-checkout`, `proc-receive`, `pre-receive`, `update`, `post-receive`, `post-update`, `fsmonitor-watchman`, `p4-*`, `sendemail-validate`.
Reason: some hooks change git behaviour by their existence (`push-to-checkout` replaces updateInstead; `post-index-change` fires on every index write). Repos here do not use them.

R3. `tollgate install` must add to the `env` object of `~/.claude/settings.json`: `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=core.hooksPath`, `GIT_CONFIG_VALUE_0=<absolute hooks dir>`. It must keep every other key and key order.
Reason: Claude Code documents `env` as applied to every session and its subprocesses. Scope is then "processes started by Claude Code". Victor's terminal has no injection (Victor, 2026-11-05).
UNVERIFIED: that `env` reaches Bash calls of Workflow and Task subagents and Claude Code's internal git helper. The guard's self-check (R31) turns a missing injection into a deny instead of a silent fail-open. Fallback if `env` does not reach subagents: the guard rewrites the Bash input (`updatedInput`, documented) to prefix the three exports.

R4. Scope. A repo is in scope when the realpath of its common dir's parent is under one of `scope.roots` (default `["~/Repos"]`) and not under `$TMPDIR`, `~/.cargo`, `~/.cache`, `~/.bun`, `~/.local/share/uv`, or when any remote URL matches `scope.remotes`. `scope.include` (basename globs, default `["*"]`) and `scope.exclude` (default `[]`) refine the set during rollout. There is no global "every repo" scope by name.
Reason: scope by basename let a renamed clone escape and gated temp repos that test suites create (critique). Path and remote identity do not.

R5. `pre-push` must gate every push to a remote whose URL matches `scope.remotes`, whatever the local path of the repo.
Reason: an agent can clone to `/tmp` and push from there. The remote is what handoff and CI see.

R6. Out-of-scope repos: gate hooks chain the repo's own hook (R7) and exit 0.

R7. Chaining. For every installed hook name, tollgate must run the repo's own hook `<repo hooks path>/<name>` when it is executable, with the same arguments, the same stdin content (buffered, replayed) and the same cwd. Order: repo hook first for `pre-*` and message hooks, tollgate first for `reference-transaction`. A non-zero exit of the repo hook is the hook's exit. The repo hooks path is `core.hooksPath` from the repo's config files (worktree, local, global, system; parsed by tollgate without a subprocess; `include`/`includeIf` present -> fall back to `env -u GIT_CONFIG_* git rev-parse --git-path hooks`), else `<common dir>/hooks`.
Reason: the injection replaces the repo's `core.hooksPath` (verified). agent_v's `.githooks` must still run. No subprocess on the hot path: a 60-commit rebase fires about 1300 `reference-transaction` calls (verified).

R8. tollgate must not read any environment variable to decide "enforce or not". There is no `TOLLGATE=0`.
Reason: an env switch is a one-line bypass.

R9. `reference-transaction` must exit 0 at once in states `preparing`, `committed` (after the ledger update of R29) and `aborted`, after draining stdin, with no subprocess unless the repo has its own `reference-transaction` hook. Unknown states exit 0.

### 4.2 Decision rules per hook

R10. Zero oid and symref values. The zero oid length follows `git rev-parse --show-object-format` (40 or 64). A value that starts with `ref:` is a symref. Any `refs/heads/*` update whose new value is a symref must be denied. R11a is evaluated on the ref name before the values are parsed.
Reason: `git clone` and `git checkout` emit `ref:` lines for `HEAD` (verified); a symref on a branch would let a fast branch move a full ref.

R11. `reference-transaction`, state `prepared`, per stdin line `<old> <new> <ref>`, in this order:
  a. `ref` not under `refs/heads/` -> allow, except: `refs/replace/*` -> deny (R12); `refs/remotes/*` -> R13.
  b. `new` is zero and `old` is non-zero -> deletion -> allow.
  c. `old` and `new` are both zero -> rename or copy target with an unknown value (verified). Full ref -> deny with the message "rename onto <ref> is not allowed; use tollgate merge". Other ref -> allow and write a ledger note (R29).
  d. `new` equals `git rev-parse --verify -q <ref>` -> no-op -> allow. The `old` on stdin is not used (it is zero when the caller gave no expected value, verified).
  e. `new` differs only in case from an existing branch name on a case-insensitive filesystem (`core.ignorecase=true`) -> deny.
  f. A pending-commit marker for this git process exists (R18) and `new^{tree}` equals its tree -> tier `fast`, continue at R15.
  g. Otherwise tier = `tier_for_ref(ref)` (R27), continue at R14.

R12. All tollgate git calls run with `GIT_NO_REPLACE_OBJECTS=1`. `refs/replace/*` updates are denied by `reference-transaction`; the guard denies `git replace` text.
Reason: a replace ref made tollgate check another tree than the one pushed (verified).

R13. `refs/remotes/*` updates (best effort): denied when the parent git command (Linux `/proc/<ppid>/cmdline`, macOS `proc_pidpath` + `KERN_PROCARGS2`) is `update-ref`, `branch`, `symbolic-ref`, `reset`, `checkout`, `switch`; otherwise allowed. The guard also denies `update-ref refs/remotes` text.
Reason: remote-tracking refs are inputs to the fast-tier exemptions (R16). Making them hard to forge keeps those exemptions meaningful. Full refs never trust remote-tracking refs (R14).

R14. Required tier `full` (ref update, merge, push): only two outcomes. (1) A `full` record for `new^{tree}` exists -> allow. (2) `new` equals the trusted remote's current `refs/heads/<branch>` as returned by `git ls-remote <remote> refs/heads/<branch>` at hook time, for a remote in `scope.remotes` -> allow, write "remote-verified" to the ledger. Otherwise start or attach a `full` job (R15). No reachability, reflog or `ORIG_HEAD` exemption applies to a full ref.
Reason: exemptions based on other local refs let fast-only trees into `main` through ff-merge, `branch -f`, `reset --hard` and `fetch . feat:main` (critique). `ls-remote` is bypass-resistant: the remote `main` is GitLab-protected and reached only through the gated push.

R15. Record lookup and job. Look up (tree, tier, fingerprint, selection) per R78-R83. Hit -> allow. `fail` -> deny with the stored report (R42). `timeout`/`error` inside their TTL -> deny with the stored report. Else start or attach the job and wait up to the inline budget (R38).

R16. Required tier `fast` on `reference-transaction`: the update is allowed without a lookup when `new` is reachable from a `refs/remotes/<trusted>/*` ref whose latest reflog entry message starts with `fetch`, `pull` or `update by push`; or when `new` is reachable from another `refs/heads/*` ref; or when `new` appears in the reflog of `ref` with a tollgate `allowed` note (R29). `ORIG_HEAD` is never trusted.
Reason: for feature branches the hard gate is the push (R20). These exemptions keep `pull`, `checkout -b`, `reset` to an earlier state and `rebase --abort` working. They do not apply to full refs (R14).

R17. `pre-commit` and `pre-merge-commit` compute `T` with `git write-tree` under the `GIT_INDEX_FILE` git gave the hook, never `.git/index` directly. Base = `HEAD^{tree}` (empty tree on an unborn branch). Tier: `pre-commit` -> `fast` on every branch, including full refs; `pre-merge-commit` -> `tier_for_ref(current branch)`.
Reason: Victor: fast on every commit, full at handoff and merge. A commit on `main` gets `fast`; the push of `main` and merges into `main` get `full` (R14, R20). Partial commits and `commit -a` use temporary index files, and the hook's write-tree equals the commit tree in every case (verified).

R18. Pending-commit marker. On pass, `pre-commit` writes `<ledger>/pending/<ppid>-<git start time>.json` = {tree, time}. `reference-transaction` reads the marker for its own ppid (same git process; pid plus process start time, so a reused pid does not match), uses it once, deletes it. Markers older than 1 h are ignored and removed.
Reason: tells a commit on `main` (fast) from a merge, ff, reset or `branch -f` on `main` (full) without parsing commands.

R19. Sequencer operations (`cherry-pick`, `revert`, `am` on a branch) update `refs/heads/<b>` once per commit with no `pre-commit` (verified; the draft's claim was wrong). Rules: a sequence is in progress when `<git dir>/sequencer/todo`, `CHERRY_PICK_HEAD`, `REVERT_HEAD` or `rebase-apply/` exists with commands still pending. On a fast ref, intermediate updates are allowed without a check and tollgate writes `<ledger>/seq/<ref>.json` = {base: the ref's value at the first update}. The final update (no pending commands) is gated with base from that file, then the file is removed. On a full ref an intermediate update is denied with the message "run the sequence on a temporary branch, then tollgate merge". `git rebase` writes `HEAD` while detached and the branch once at the end (verified): the final update is gated with base = the ref's tree before the rebase (R62).
Reason: N serial inline jobs per pick is problem 2 again. The tip is what gets pushed.

R20. `pre-push` reads stdin lines `<local ref> <local oid> <remote ref> <remote oid>`. For each line: remote ref not under `refs/heads/` (tags, notes) -> allow; local oid zero (deletion) -> allow; remote URL matches `scope.remotes` -> tier `full` unless the branch matches `push.fast_refs` (default `[]`), then `fast`; other remotes -> `tier_for_ref(remote ref)`. The record of `<local oid>^{tree}` at that tier must exist (R14 outcome 1 or a `fast` record) or the push is denied. `pre-push` applies no exemption of R14(2) or R16.
Reason: handoff to the Mac and to the follower is a push. Victor: full at the branch tip before handoff. Q2 asks which branches may push with `fast`.

R21. Ref updates on a detached `HEAD` are not gated.

R22. Tags are not gated (D4 of draft 1 kept). A tag points at a commit that was gated when it became a branch tip, and GitLab CI runs on tags.

### 4.3 Guard (Claude Code PreToolUse)

R23. The guard is registered in `~/.claude/settings.json` with the command `<data dir>/tollgate/bin/tollgate guard`, matchers `Bash` and `Write|Edit|MultiEdit|NotebookEdit`, `timeout: 10`, `"onFailure": "block"`. It exits only 0 or 2. `main` is wrapped in `catch_unwind`; a panic exits 2. Malformed input exits 2.
Reason: exit 2 is the only exit code documented to block in all cases. `onFailure: block` covers a timeout (Claude Code >= 2.1.295; local is 2.1.317). A missing binary also blocks under `onFailure: block`. UNVERIFIED whether exit 101 blocks, so tollgate never exits 101.

R24. Self-check on every call: the guard's own environment must contain the three `GIT_CONFIG_*` values of R3 exactly as written at install (read from `<data dir>/tollgate/install.json`); the hooks dir must exist; each installed hook must be a hard link to (same device and inode as) the running guard binary. Any failure denies the Bash call (every Bash call, not only git) with one line: `tollgate: gate not armed (<reason>); run: tollgate install`.
Reason: this is the fail-closed answer to a missing hooks path or dangling hook (verified fail-open in git), to settings synced from the other machine with another `$HOME` (Q11), and to a project `settings.local.json` that overrides `env` (UNVERIFIED). Denying all Bash makes the broken state loud at once.

R25. Bash text rules. The guard normalizes the command (lowercase, collapse whitespace, strip quotes) and denies (exit 2, one-line reason) when it contains: `--no-verify`; `-n` as a flag of `git commit`, `git am` or `git push`; `-c <key>` or `--config-env` where key matches `core.hookspath`, `core.hooks*`, `include.*`, `includeif.*`, `alias.*`; `git_config_count`, `git_config_key`, `git_config_value`, `git_config_parameters`; `env -i`, `env -u git`, `unset git_config`, `export git_config`; `git send-pack`, `git receive-pack`, `git replace`, `git symbolic-ref refs/heads`, `git update-ref refs/remotes`; `git branch` with `-m`, `-M`, `-c`, `-C`, `--move`, `--copy` whose target matches a full ref; `tollgate waive`, `tollgate policy approve`, `tollgate baseline record`; a write to the tollgate state, data or config dir (redirection, `rm`, `mv`, `cp`, `tee`, `sed -i`, `truncate` with a path under it). Reads of the state dir are allowed. The same substring rules also run on the words as bash passes them, one command at a time: ANSI-C quoting (`$'\x2d-no-verify'`, `$'\x47IT_CONFIG_COUNT'`) is decoded as bash decodes it, so an escape cannot hide a flag or a variable name from the text match (S1, S2). The decoder finds the end of `$'...'` first, as bash does (a backslash escapes the next character), so `$'\c\\'` is one control character and the quote after it closes the string.
Item 31 (21c, fail closed): in a command whose text (raw or normalized) names `git` or `tollgate`, the guard does not decode; it denies any `$'`, any `\c`, and text fed to a shell (`sh`, `bash`, `zsh`, `dash`, `ksh`, `mksh`, `ash`, `fish`, `busybox`, `source`, `.`, also behind `env` and the other wrappers) through a pipe, a heredoc, a here-string or an input redirection, and a heredoc or here-string fed to `python*` or `perl` (a pipe into them only when they read their program from stdin). The decoder stays for commands that do not name git or tollgate (`$'\x67it' commit -n`).
X1: assignments of `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_SSH_VARIANT`, `GIT_PROXY_COMMAND` and `GIT_EXEC_PATH` for git or tollgate (in front of the command, through `env`, or exported for the rest of the shell) are denied, like the R8 dir variables.
Reason: these remove or evade the hook (verified for lowercase `-c`, `include.path`, `--config-env`, `send-pack`), or move a full ref without showing the value. Reads must stay open so agents can read logs (R96). A decoder that differs from bash in one escape lets the rest of the command hide inside a quote (review R2: `echo $'\c\\' ; git commit -n` passed); denying the constructs is exact where decoding is not. `GIT_EXEC_PATH` also comes first on the hooks' `PATH`, so it picks the `git` the gate hooks run.

R26. Ask rules (`permissionDecision: "ask"`): Bash `git config` writing `core.hooksPath`, `include*`, `alias.*`, `url.*`, `core.sshCommand`, `core.gitProxy`, `ssh.*`; `git branch -m/-M/-c/-C` to a non-full ref; `rm`/`mv` of `.git/**/*.lock`; Write/Edit whose `file_path` is any `.claude/settings*.json`, the host config, a policy file (R71), under `.git/`, `.githooks/`, or any `core.hooksPath` dir. Write/Edit under the tollgate state, data or config dirs -> deny.

R27. `tier_for_ref(ref)`: strip `refs/heads/` or `refs/remotes/<remote>/`; match the branch name against `tiers.full_refs` case-insensitively; match -> `full`, else `fast`. Default `full_refs = ["main", "master"]`; a repo may extend it (Q1).
Reason: APFS is case-insensitive by default; `MAIN` and `main` are one loose ref file.

R28. Bash timeout rewrite. For a Bash command that runs `git commit|merge|rebase|cherry-pick|revert|am|pull|push|reset` or `tollgate check|wait|merge`, the guard returns `updatedInput` with the same input plus `timeout: 600000` (when absent or lower) and the command prefixed with `TOLLGATE_INLINE_CAP=540 `. A hook uses inline budget = min(`budget.inline` from config, `TOLLGATE_INLINE_CAP` seconds when present, else 100 s).
Reason: the Bash default timeout is 120 s and the maximum 600 s (documented). A hook that waits longer than the Bash timeout leaves a backgrounded `git commit` holding `index.lock` while the agent retries (critique). An agent cannot abuse the env value: it only shortens or, bounded by config, lengthens the wait. UNVERIFIED that `updatedInput` may change `timeout`; if not, the default 100 s stands.

### 4.4 Ledger and tamper detection

R29. Ledger at `$XDG_STATE_HOME/tollgate/repos/<repo key>/` (repo key = `blake3(realpath(common dir))[..16]`): `tips.json` (last allowed oid per full ref, and remote-verified oids), `pending/`, `seq/`, `policy-approved.json`, `reflog-notes.json` (oids tollgate allowed per ref, for R16). `reference-transaction` in `committed` updates `tips.json` for full refs it allowed and appends allowed oids for fast refs.

R30. Tamper report. At the start of every gate hook, tollgate compares each full ref's current value with `tips.json`. A difference whose tree has no `full` record and is not remote-verified is written as `tips.json.moved = {ref, from, to, seen}`. It is printed as a WARNING in every deny report and in `tollgate status` and `tollgate audit`. It does not deny unrelated commits. The next `full` record for that tip clears it.
Reason: rename on the files backend and all updates on reftable are invisible to the hook (verified). Victor's own terminal commits on `main` also move it outside tollgate and must not block the agents. What leaves the machine is gated by R14 and R20 regardless of local tips.

### 4.5 Fail closed and budgets

R31. Every exit path of a gate hook is an explicit decision. When the decision function returns an error, the hook denies and prints the error.

R32. A hook that did not get a record inside its inline budget must deny. The job continues detached. The deny message names the job id and `tollgate wait <job>`.

R33. Budgets. Host config `[budget]`, overridable per repo: `inline = "100s"` (hook wait; the guard may raise it to 540 s per R28), `queue = "30m"` (time a job may wait for a verify slot and resources; no record is written on expiry, the job is marked `deferred`), `fast = "20m"`, `full = "2h"` (wall clock, counted from the first step start, not from spawn). On expiry the runner kills the step (R35) and records `timeout`.
Reason: queue time counted as job time turned contention into cached denials (critique).

R34. Verdict classes and caching. `fail` from a step that ran to completion is deterministic: cached, denies the same key until `tollgate check --rerun`. `timeout` and `error` are environmental: the record carries `ttl = 15m`; inside the TTL a hook denies with the stored report and does not start a job; after the TTL the next hook starts a new job. `error` with cause `disk`, `docker`, `deferred` writes no record at all; the hook denies with the cause.

R35. Process control. Each step runs in its own process group with the runner as `PR_SET_CHILD_SUBREAPER` on Linux (orphans reparent to the runner). On expiry: SIGTERM to the step's leader, wait `step.grace` (default 60 s for `nextest`, which forwards the signal to its test processes; 10 s otherwise), then SIGKILL every process in the group and every descendant found by a process-tree walk (`/proc` on Linux, `proc_listchildpids` on macOS). A resource slot is released only when that set is gone.

R36. nextest runs carry `global-timeout` and `slow-timeout` with `terminate-after` smaller than the job limit, so a hung test fails inside the runner first.

R37. A hook killed by Claude Code, by the user or by OOM aborts the git operation (verified). tollgate does not depend on cleanup code in the hook. All state transitions are files written by atomic rename or kernel locks released on process death.

R38. Jobs are detached from the hook: `fork`, `setsid`, stdio to the job log, `env_clear` (R52). On macOS and Linux via `Command::pre_exec` with `libc::setsid`.

R39. Stale git locks. A hook never deletes or names `rm` for a lock file. `tollgate doctor --repo <p>` reports a lock (`index.lock`, `HEAD.lock`, `refs/**/*.lock`) as stale only when no live git process has the repo or one of its worktrees as cwd (process-tree walk) and the lock is older than 2 minutes. The hook's deny report mentions only `tollgate doctor --repo .` when a lock older than 2 minutes exists that the parent git process does not own.
Reason: during `commit -a` and in `prepared` the parent git holds live locks (verified). Printing `rm` taught agents to delete live locks.

### 4.6 Exact tree, verify checkout, job environment

R40. What is checked is the tree `T` of R11, R17, R19 or R20. Never a working tree. Never the index of another worktree.

R41. Verify checkouts live at `<verify.root>/<repo key>/<tier>/wt` (default root `$XDG_STATE_HOME/tollgate/verify`; Q5 for the disk). Default one checkout per tier per repo clone (`verify.slots = { fast = 1, full = 1 }`); more slots make `wt2`, `wt3`. Creation: `git worktree add --detach --no-checkout --lock --reason tollgate <path> <anchor>`, where anchor = `HEAD` when it resolves, else a commit made with `git commit-tree` of the empty tree (dangling, no ref).
Reason: a registered worktree keeps tools that query git (vergen, `git describe`) working; `--lock` protects against `worktree prune`. `worktree add ... HEAD` fails in an unborn repo (verified). Separate fast and full checkouts stop a 2 h full job from queueing every fast commit behind it (critique).

R42. Before a job, inside the verify checkout with the lock held: `git read-tree -u --reset <T>`, then `git clean -ffdx -e target -e node_modules -e .venv -e <each step cache_dirs entry>`, then `git status --porcelain` must be empty and `git write-tree` must equal `T`. Mismatch is verdict `error`. After the last step, `git status --porcelain --ignored=no` must still be empty; a step that changed tracked files makes verdict `error` with the file list.
Reason: `read-tree -u --reset` with a tree oid updates only changed files, keeps mtimes, keeps ignored dirs and needs no commit (verified). It also keeps untracked non-ignored files (verified), which `clean` removes. `stash --keep-index` is rejected: it mutates the agent's checkout.

R43. The verify checkout owns its build outputs (`target/`, `node_modules/`, `.venv/`). It never shares `CARGO_TARGET_DIR` with agents' checkouts or with the other tier.
Reason: workspace crates rebuild whenever the checkout path differs (verified); a stable path with its own target dir is the best incremental case and avoids build-dir lock contention.

R44. Disk. Host config `verify.root`, `verify.min_free = "30G"`, `verify.max_target = "40G"` per checkout. Before a job, free space under `min_free` -> job `deferred`, no record, deny with the disk message. After a job, a target dir above `max_target` -> `cargo clean -p` of packages not in the current workspace, then full `cargo clean` if still above. `tollgate doctor` prints disk use per checkout. On the Mac, `cargo-guard.sh` must learn `verify.root` (change in agent_v `scripts/`, tracked in Q5).
Reason: myapp's target is 20 GB; `/home` has 83 GB free; cargo-guard refuses builds under 25 GB and cleans only `~/Repos/gatehouse*`.

R45. Setup steps (`[[setup]]`, R70) run inside the verify checkout after R42 when any of their `when` paths' blob oids differ from `<checkout>/.tollgate-setup.json`. Detection (R72) adds `bun install --frozen-lockfile` per TS root and `uv sync --frozen` per Python root automatically.
Reason: a tree checkout has no `node_modules` or `.venv`; `bunx` without them downloads the latest tool (critique).

R46. Tools from lockfiles run from the project: `node_modules/.bin/<tool>` and `bun run <script>`, never `bunx` with auto-install; `uv run --no-sync <tool>` after the setup `uv sync --frozen`. Missing tool -> verdict `error` with cause `setup`.

R47. CI mode `tollgate run --tier <t> --here [--report junit]` runs the steps in the current directory with no verify checkout and no result cache, exits non-zero on fail, writes `report.json` (and `junit.xml`). When a host config exists it takes the same resource slots (R86) unless `--no-host-locks` is given (hosted runners only).
Reason: the GitLab runner on this workstation shares the test Postgres with local jobs; without slots the "too many clients" storm returns (critique).

R48. `tollgate gc` removes verify checkouts whose repo is gone, records older than 90 days, bulky step logs older than 14 days (keeping `report.json` and `junit.xml` as long as the record, R82), tickets and markers older than 1 day.

R49. Policy base checkout. Policy files (R71) that differ between `T` and the base are read from the base with `git show <base commit>:<path>` into the job dir; nextest gets `--config-file <that file>`; baseline steps read the base baseline file. The checkout itself stays at `T`.

R50. Selection metadata (`cargo metadata`, `package.json`, `pyproject.toml`) is read from the verify checkout at `T`, never from the agent's checkout.

R51. The hook itself runs no tool in the agent's checkout except `git`. No `uv run`, `bunx`, `cargo` in the hook.
Reason: `uv run` syncs the agent's `.venv` and may use the network; `bunx` downloads (critique).

R52. Job environment. The runner starts every setup step, step and verify-checkout git call with `env_clear()` and then: `PATH` (tollgate-built: `~/.cargo/bin`, `~/.local/bin`, `~/.bun/bin`, `/usr/local/bin`, `/usr/bin`, `/bin`, plus `job.path_prepend` from host config), `HOME`, `USER`, `LOGNAME`, `SHELL`, `LANG=C.UTF-8`, `LC_ALL=C.UTF-8`, `TERM=dumb`, `CI=1`, `TOLLGATE=1`, `TMPDIR=<job dir>/tmp`, `CARGO_HOME`, `RUSTUP_HOME`, `DOCKER_HOST`, `SSH_AUTH_SOCK` (only when `job.allow_ssh_agent = true`), host config `[job.env]`, repo `[[step]].env` and `env_file` entries. No `GIT_*` variable is passed, so the injection does not reach test suites and test repos are not gated. Hook git calls that are not about the hook's own index run with `GIT_INDEX_FILE`, `GIT_DIR`, `GIT_WORK_TREE`, `GIT_PREFIX` removed and `-C <repo>` set. Verify-checkout git calls set `GIT_DIR` and `GIT_INDEX_FILE` explicitly for that checkout.
Note (item 38): `CARGO_HOME` and `RUSTUP_HOME` are never taken from the environment that started the job (`CARGO_HOME=/tmp/x git commit` would put `/tmp/x/bin` first on the job `PATH`). They come from host `[job] cargo_home` and `rustup_home` (`~` expands), else `<home>/.cargo` and `<home>/.rustup`, where home is the job `HOME` (for hooks the one `install.json` records, R8). The runner process does not keep them either.
Reason: inherited `GIT_INDEX_FILE=<agent repo>/.git/index.lock` made `read-tree` overwrite the agent's index (verified). Inherited application env (`GUARD_EVAL_ONLY`, `GATEHOUSE_*`) made a pass depend on one agent's shell.

### 4.7 Tiers and selection

R53. A lookup for tier `fast` accepts a `full` record. A lookup for `full` accepts only `full`.

R54. Each step declares `tiers = ["fast", "full"]` (default both). `full` runs every step on the whole workspace, selection disabled. `fast` runs steps with selection enabled.

R55. Changed paths for selection: `git diff-tree -r -z --name-status <base tree> <T>`. Base per hook: R17 `HEAD^{tree}`; R11/R19 the ref's current tree, or the sequence base, or the pre-rebase tip tree; R20 the remote oid's tree when it is present locally, else the empty tree.

R56. Base trust. Selection relative to a base is sound only when the base was checked. A base is trusted when its tree has a record at `fast` or above, or when the base commit is reachable from a `refs/remotes/<trusted>/*` ref whose value the trusted server reported (CI covers it; L2 note on anchor provenance). An untrusted base, an empty diff with no record for `T`, or a base that is the empty tree makes `fast` run with selection disabled (whole workspace, fast steps only).
Reason: an empty diff on top of an unchecked commit must not produce a pass for a tree nothing checked (critique).

R57. Rust selection (workspace root: `Cargo.toml` with `[workspace]` or a single package):
  a. Global triggers mark the whole workspace: root `Cargo.toml`, `Cargo.lock`, `.cargo/**`, `rust-toolchain`, `rust-toolchain.toml`, `.config/nextest.toml`, `tollgate.toml`, `.sqlx/**`, `clippy.toml`, `rustfmt.toml`, `build.rs` of any package, plus `select.global` globs.
  b. `select.owners` maps globs to packages (`"migrations/**" = ["gatehouse-core"]`). A package name that is not in the `cargo metadata` of `T` marks the whole workspace and prints `WARN owners: unknown package <name>`.
  c. Any other path maps to the package whose manifest dir is its longest prefix.
  d. A path under no rule and no package marks the whole workspace. Deletions count.
  e. Affected `A` = reverse-dependency closure of the marked packages including dev-dependency edges (`guppy` on the full `cargo metadata` of `T`).
Decision D7: `determinator` is reserved for a later version (`select.engine = "determinator"`). Reason: its base-graph behavior for new crates and offline was left open. The prefix rule errs toward running more.

R58. Rust step kinds (fast uses `A`, full uses the workspace):
  - `cargo-fmt`: `cargo fmt --all --check`, always whole workspace.
  - `cargo-clippy`: `cargo clippy <-p ...|--workspace> --all-targets -- -D warnings`.
  - `nextest`: `cargo nextest run --config-file <effective nextest config, R49> --tool-config-file tollgate:<generated> --profile tollgate-<tier> --no-fail-fast --no-tests pass -E '<filterset>'`. Filterset per `select.fast.tests`: `rdeps-unit+changed-integration` (default): `(rdeps(a)|rdeps(b)) & !kind(test) | (package(a)|package(b)) & kind(test)`; `rdeps-all`: `rdeps(a)|rdeps(b)`. Empty selection exits 4 without `--no-tests pass` (verified). Q3.
  - `cargo-doctest`: `cargo test --doc <-p ...>` (nextest skips doctests, verified).
  Any failure to compute metadata or a filterset runs the whole workspace.

R59. TypeScript/Bun (root: `package.json` + `bun.lock`/`bun.lockb`, repo root and one level): `biome` (`node_modules/.bin/biome check --no-errors-on-unmatched <changed files>`; whole root in full), `tsc` or `svelte-check` (whole root), `bun-test` (`bun run test`, whole root, both tiers by default). No change under the root -> skipped in `fast`.

R60. Python (root: `pyproject.toml`, root and one level): `ruff` (`uv run --no-sync ruff check --force-exclude -- <changed>` and `ruff format --check`), `pyright-baseline`, `pytest-baseline` (R99). Skipped in `fast` when nothing under the root changed. Q10 for the pytest tier.

R61. Docs-only. A `fast` job passes with zero steps and writes a record when every changed path is docs-only. A path is docs-only when it matches `select.docs_only` globs from policy, or (built-in list, `*.md *.mdx *.rst *.txt *.png *.jpg *.jpeg *.gif *.svg *.webp`) when it is outside every detected code root, matches no `select.global` or `select.owners` glob, is not a policy file, and is not under `**/tests/**`, `**/fixtures/**`, `**/src/**`, `prompts/**`, `migrations/**`. An empty diff is not docs-only (R56).
Reason: myapp embeds `tests/fixtures/sum.png` with `include_bytes!` and loads `prompts/*.md` (critique).

R62. Rebase and sequence bases: R19. Fast records store their selection (R80), so a later lookup with a larger diff does not hit a smaller selection.

### 4.8 Policy: repo config, base, approval

R63. Config file `tollgate.toml` at the repo root, committed. Schema (`version = 1`):

```toml
version = 1

[tiers]
full_refs = ["main", "integration/*"]       # default ["main", "master"]; case-insensitive

[push]
fast_refs = ["wip/*"]                       # pushes to trusted remotes that need only fast (default [])

[budget]
inline = "100s"
fast = "20m"
full = "2h"

[policy]
files = ["prompts/guard_policy.md"]         # extra files treated as policy (R71)

[select]
global = [".sqlx/**", "prompts/**"]
docs_only = ["docs/**", "*.md"]
[select.owners]
"migrations/**" = ["gatehouse-core"]
[select.fast]
tests = "rdeps-unit+changed-integration"    # or "rdeps-all"
pg_tests = ["gatehouse-api::*", "gatehouse-core::*", "gatehouse-agent::*"]   # nextest pg group

[[setup]]
name = "bun install"
run = "bun install --frozen-lockfile"
cwd = "dashboard"
when = ["dashboard/bun.lock", "dashboard/package.json"]

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
resources = ["cpu", "pg", "minio"]
[[step]]
name = "doctests"
kind = "cargo-doctest"
resources = ["cpu"]
[[step]]
name = "dashboard check"
kind = "svelte-check"
cwd = "dashboard"
[[step]]
name = "ios lint"
kind = "command"
run = "swiftlint lint --strict"
cwd = "ios"
only_on = ["macos"]
tiers = ["full"]
when = ["ios/**"]
resources = ["cpu"]
timeout = "10m"
cache_dirs = ["ios/.build"]

[[quarantine]]
test = "gatehouse-api::sessions test_concurrent_cancel"   # <package>::<binary> <test>, exact
until = "2026-12-01"
issue = "Issues/open/myapp-cancel-flake"
```

Common step fields: `name`, `kind`, `cwd`, `tiers`, `when`, `resources`, `timeout`, `grace`, `only_on`, `env`, `env_file` (outside the tree, hashed into the key), `cache_dirs`.
Reason: TOML matches Victor's Rust CLIs; built-in kinds give parsing and selection; `command` gives escape room.

R64. Config validation runs per job against `T`'s metadata: unknown `owners` packages (R57b warn + whole workspace), unknown `quarantine` tests (`error`: the entry must match a listed test), `until` more than 30 days after the committer date of the policy commit (R71) -> `error`. `tollgate config --check` runs the same validation locally.

R65. Detection (no `tollgate.toml`): roots per R57, R59, R60 at the repo root and one level (skipping `node_modules`, `dist`, `build`, `target`, `vendor`, dot-dirs), with the setup steps of R45. `tollgate config --effective` prints it; `tollgate init` writes it for review. The effective config hash is part of the fingerprint.

R66. Policy base. For a job on ref `R` with new commit `N` (or index tree on `HEAD`): anchors = `refs/remotes/<trusted>/main` (and other full refs on trusted remotes), then local full refs. `M = git merge-base N <anchors>` (nearest). Candidates = commits in `git log --first-parent --format=%H M..N -- <policy files>` whose policy blob set (blake3 of `git ls-tree N -- <policy files>` output) is in `policy-approved.json`. Policy commit = the newest candidate, else `M`. With no anchor (new repo), policy commit = `N` itself.
Reason: reading policy from the tree under test, or from its parent, lets two commits weaken the gate (critique). Anchors on protected remote refs cannot be moved locally.

R67. When `T`'s policy blob set equals the policy commit's set, `T`'s own policy applies. Otherwise: steps = union of the policy commit's steps and `T`'s steps (by name; a step removed in `T` still runs; a step added in `T` runs too); `select`, `tiers`, `push`, `budget`, `quarantine`, baselines and nextest config come from the policy commit (R49). The report prints `POLICY: using base policy from <commit>; approve with: tollgate policy approve <rev>` .

R68. `tollgate policy approve <rev>` records `rev`'s policy blob set hash with time and reason in `policy-approved.json`. It requires an interactive TTY on stdin and stdout (`std::io::IsTerminal`); Claude's Bash has none. The guard also denies the text (R25). Approval is per blob set, so the same policy content approved once is valid on every branch.

R69. Quarantine `until` is capped at 30 days after the policy commit's committer date (R64). No auto-extension.

R70. `[[setup]]` fields: `name`, `run`, `cwd`, `when`, `env`, `timeout` (default 10 m). Setup steps are policy too (they come from the policy commit under R67).

R71. Policy files: `tollgate.toml`, `.config/nextest.toml`, `.pyright-baseline.json`, `.pytest-baseline.json` (any depth, for Python roots one level down), plus `policy.files`. The guard asks on edits (R26). Policy files are never docs-only.
Note (tool configs, items 3, 5, 6): cargo, clippy and rustfmt configs (`.cargo/config.toml`, `.cargo/config`, `clippy.toml`, `.clippy.toml`, `rustfmt.toml`, `.rustfmt.toml`, any depth) are policy files too; the job writes the policy commit's version (or removes the tree's) in the verify checkout. A tree entry named `.cargo` of any mode is one as well. After the overlay, the job refuses (verdict `error`, cause `checkout`) a symlinked tool config, a `.cargo` symlink whose target holds cargo config, and a dir symlink whose target is not tree content (outside the checkout, or in a kept dir) and holds a file with a tool-config name. The policy commit's own links count: a branch can change their targets.

R72. nextest tool config. tollgate passes `--tool-config-file tollgate:<generated>` with profiles `tollgate-fast` and `tollgate-full` (retries, slow-timeout, global-timeout, junit path, `[test-groups] pg` with `max-threads` from the host config, override assigning `pg` to `select.fast.pg_tests`). The repo's `.config/nextest.toml` (from the policy commit, R49) has higher priority (verified).

R73. `tollgate ci-snippet --gitlab` prints a `.gitlab-ci.yml` job that runs `tollgate run --tier full --here --report junit` and publishes the JUnit report.

### 4.9 Result cache

R74. Key = `blake3` of canonical JSON `{schema, checks_schema, tree, tier, fingerprint}`. `checks_schema` is a constant in the binary, bumped on every change to step kinds, selection, parsing or verdict logic. Fingerprint = sorted map of: tollgate version; `rustc -vV`, `cargo --version`, `cargo nextest --version` (Rust roots); `bun --version` (TS); `uv --version` (Python); `git --version`; blake3 of the host config; blake3 of each `env_file`; the effective config hash (R65); blake3 of the built job environment (R52) without `TMPDIR`; `uname -sm`; for steps with `pg`/`minio` resources, the local image id of `resources.<name>.image` (`docker image inspect --format {{.Id}}`) when configured.
Reason: the tree covers lockfiles, repo config, nextest config and source. Tools pinned by lockfiles (biome, ruff, pyright, tsc) are covered by the tree and the setup. Toolchain, host config, environment, image and tollgate's own logic are the outside inputs.

R75. Version strings are cached in `$XDG_STATE_HOME/tollgate/toolcache.json` by binary realpath, size and mtime. A hook does no tool subprocess on a cache hit.

R76. Records live at `$XDG_STATE_HOME/tollgate/results/<key[..2]>/<key>.json`, written by atomic rename. Content: tree, tier, verdict, verdict class, ttl, fingerprint, policy commit, base tree, selection (R80), started, finished, duration, host, tollgate version, job id, steps `[name, status, duration, exit, log path, failing items]`, flaky list, quarantine hits.

R77. Records are shared by every worktree and clone of a repo on the machine. Not shared between machines in v1 (Q9).

R78. Lookup for `full`: a `full` record with verdict `pass` for the key.

R79. Lookup for `fast`: a `full` pass; or a `fast` pass whose `selection` is `all`; or a `fast` pass whose `selection.base` equals the current base tree; or a `fast` pass whose selected packages and roots are a superset of the selection needed for the current base.

R80. `selection` in a record: `all`, or `{base, packages: [..], roots: [..], steps: [..]}`.

R81. A `pass` record whose `report.json` is missing from `jobs/<job id>/` is invalid and treated as no record. A record also counts only as the record of its own key (its tree, tier and fingerprint hash to the file name) and only when its `report.json` says the same job, tree, tier and verdict; the store refuses to write any other (S11).
Reason: a one-word edit of a record file (`fail` to `pass`) or a copy of another tree's pass record must not let a tree through. Same-user code can still write two consistent files: that is out of scope (section 1).

R82. Job dirs `$XDG_STATE_HOME/tollgate/jobs/<job id>/` hold `<step>.log`, `report.json`, `junit.xml`. `report.json` and `junit.xml` live as long as the record (R48).

R83. Poisoning. Records are written only by the job runner. The guard denies writes under the state dir (R25, R26). `tollgate audit [--since]` lists records with duration, job log size, tollgate version and `moved` tips (R30), so a 0 s pass or an old-version record stands out. Waive records (R113) carry `waived: true` and a synthetic job dir with the waiver text. The README states the same-user limitation.

### 4.10 Concurrency and scheduling

R84. Host config `$XDG_CONFIG_HOME/tollgate/config.toml`:

```toml
[scope]
roots = ["~/Repos"]
remotes = ["*gitlab.com:victorkwak/*", "*gitlab.com/victorkwak/*"]
include = ["baton", "wikiknit"]          # rollout; ["*"] = every repo under roots
exclude = ["agent_v"]

[resources]
cpu = 2
pg = { slots = 1, image = "postgres:16" }
minio = { slots = 1, image = "minio/minio" }

[nextest]
pg_max_threads = 8                       # <= postgres max_connections / 6
retries = 2
slow_timeout = "120s"
terminate_after = 2
global_timeout_fast = "15m"
global_timeout_full = "100m"

[verify]
root = "/mnt/data1/tollgate/verify"      # Q5
slots = { fast = 1, full = 1 }
min_free = "30G"
max_target = "40G"

[budget]
inline = "100s"
queue = "30m"
fast = "20m"
full = "2h"

[job]
path_prepend = []
allow_ssh_agent = false
[job.env]
SQLX_OFFLINE = "true"
```

R85. Resource semaphores: `$XDG_STATE_HOME/tollgate/locks/<resource>/slot-<i>`, `File::try_lock` exclusive (`flock(2)`, Linux and macOS; Rust >= 1.89). A step takes its resources in one canonical order (sorted by name), all-or-nothing: if any slot is not free it releases those it holds and waits.
Reason: hold-and-wait with per-repo order deadlocks (critique).

R86. Fairness: a waiter creates `locks/<resource>/queue/<unix nanos>-<pid>` and holds an exclusive `flock` on that ticket while it waits. A waiter may take a slot only when no older ticket is held (test: `try_lock` on each older ticket; success means the owner is dead -> remove it). Sleep 200 ms with jitter. No pid-liveness test.
Reason: `kill(pid, 0)` lies after pid reuse; macOS pid_max is 99998.

R87. Verify lock: one exclusive lock file per verify checkout, held for the whole job.

R88. Job dedupe: `jobs/by-key/<key>.lock`. A hook that finds it held attaches and waits for the record.

R89. Waiters and supersession. A waiting hook holds a `flock` on `jobs/<id>/waiters/<pid>`. A queued job (not started) with no held waiter lock is `superseded` (no record) when a newer queued job exists from the same origin (`worktree path`, `ref`). A started job runs to completion. Hooks' jobs rank before `--detach` pre-warms in the queue. `tollgate cancel <job>` marks a queued or running job cancelled (running: killed per R35, no record).

R90. The `pg` resource caps parallel jobs that touch the test Postgres across repos and worktrees; the nextest `pg` group caps DB tests inside a job. Peak connections <= `pg slots * pg_max_threads * 6` (each myapp test opens a pool of 5 plus one admin connection, verified). `tollgate doctor` prints the bound next to the container's `max_connections`, including CI jobs that take slots (R47).

### 4.11 Failure reporting and flaky handling

R91. On deny, the hook prints to stderr, at most about 80 lines: `tollgate: DENIED <hook> <ref> tree <T[..12]> tier <tier> verdict <v> job <id>`; WARNING lines from R30; `POLICY:` line from R67 when it applies; per failed step: name, exit, duration, `tollgate log <job> <step>`; for `nextest`: each failing test as `<package> <binary> <test>` from the JUnit file, then one rerun command per binary `cargo nextest run -p <package> -E 'test(=<name>)'`; for `pytest-baseline`: new failing node ids and `uv run pytest <ids>`; for `pyright-baseline`: new diagnostics (max 25); other steps: last 30 log lines; finally `tollgate report <job>` and `tollgate check --rerun`.

R92. `tollgate log <job> <step> [--tail N]` prints a step log. `tollgate report <job|tree> [--json]` prints the report. `tollgate status [--rev R] [--json]` prints records, running jobs, and the ledger state for the current `HEAD` and index trees.

R93. Flaky policy (nextest `retries`, default 2):
  - `fast`: a test that passes on retry does not fail the job. Report `FLAKY <test> (passed on try N)`; append to `$XDG_STATE_HOME/tollgate/flaky.jsonl`.
  - `full`: `--flaky-result fail`; a quarantine entry from the policy commit with `until` >= today turns it into `QUARANTINED <test> until <date> (<issue>)`, still logged.
  - Expired quarantine: the test fails.
  - `tollgate flaky [--days 14]` prints counts per test.
Q4 confirms.

R94. Python baselines: `pyright-baseline` and `pytest-baseline` reimplement the shell scripts in Rust with the same files and fingerprint (`path|rule|message`, whitespace collapsed, no line numbers), the same exit-code rules (pytest 2/3/4 never diffed; 5 with a non-empty baseline fails) and the same isolation re-run of new failures (cap 25). The baseline is read from the policy commit (R49). `tollgate baseline record pyright|pytest [--force]` requires a TTY (R68) and refuses a dirty tree.

### 4.12 Installation, migration, rollback, workflows

R95. Install: `cargo install --git <gitlab tollgate repo> --locked tollgate` on both machines, then `tollgate install`, which must: (a) copy the binary and link hooks (R1, R2); (b) check `claude --version` >= 2.1.295; (c) back up `~/.claude/settings.json` to `settings.json.tollgate-bak-<timestamp>`, add the `env` entries (R3) and the guard entries (R23) each tagged with the marker string `tollgate:` in the hook command and recorded in `install.json`, remove the `pre-commit-checks.sh` entry, print a unified diff, ask for confirmation unless `--yes`; (d) write the host config when absent; (e) run `tollgate doctor`. Re-running `tollgate install` after a `cargo install` refreshes the copy and the links.

R96. `tollgate uninstall` must remove exactly the entries recorded in `install.json` (matched by value), keep every other key and key order (`serde_json` with `preserve_order`), and use the backup only when the structural edit fails, after showing a diff. It removes the data dir and leaves state, records and verify checkouts (`tollgate gc --all` removes them).
Reason: restoring a day-1 backup loses every later edit (critique).

R97. `tollgate doctor [--repo P] [--injection]`: binary paths and versions (PATH binary vs installed copy), hook links (device+inode), settings entries, Claude Code version, the injection as seen by the current process (`--injection`, meant to run inside a Claude Bash call; the text contains no `hooksPath`), `git`, `cargo-nextest`, `bun`, `uv`, Docker and the test containers' `max_connections` with the R90 bound, writable dirs, disk per checkout, stale locks in `--repo` (R39), verify checkout health, `moved` tips (R30), GitLab protection of `main` for each `scope.remotes` project (`glab api projects/:id/protected_branches`; UNVERIFIED API shape; skipped with a warning when `glab` is absent).

R98. Migration: (1) Arch, `include = ["baton", "wikiknit"]`; (2) T-suite and `doctor --injection` from a Claude session; (3) add `myapp*`, write `~/Repos/myapp/tollgate.toml` (owners for `migrations/**`, `pg_tests`), add the CI snippet, protect `main` on GitLab; (4) `include = ["*"]`; (5) Mac, same steps, `only_on = ["macos"]` for iOS steps; (6) delete `pre-commit-checks.sh` after two weeks.

R99. Agent workflow:
  - Commit: `git commit -m ...` runs `pre-commit` inline (`fast`; often a cache hit after `tollgate check`). The guard raises the Bash timeout (R28).
  - Pre-warm: `tollgate check [--tier fast|full] [--tree T | --rev R] [--wait | --detach] [--rerun]`.
  - Verify step: `tollgate check --tier full --rev HEAD --detach`, later `tollgate wait <job> [--timeout 590s]` (exit 0 pass, 1 fail, 3 running).
  - Handoff: `git push origin feat` needs a `full` record of the tip (R20). `tollgate status --rev HEAD --json` goes into the baton message.
  - Integration merge: `tollgate merge <branch>` = `merge --no-ff --no-commit`, `check --tier full --wait`, `commit`. A plain `git merge` into a full ref denies at the inline budget and continues the job; `tollgate wait` then `git commit` completes it.
  - Sequences on a full ref: `tollgate pick <rev>...` = picks on a temporary branch, `check --tier full --wait`, ff of the full ref (one gated update).

R100. `tollgate waive --tree T --tier t --reason S` writes a `pass` record with `waived: true` and a synthetic job dir; requires a TTY; the guard denies the text. Q6 whether to ship it.

### 4.13 CLI summary

```
tollgate install [--yes] | uninstall | doctor [--repo P] [--injection]
tollgate check [--tier fast|full] [--tree T | --rev R] [--wait | --detach] [--rerun]
tollgate wait <job> [--timeout D] | cancel <job>
tollgate status [--rev R] [--json] | report <job|tree> [--json] | log <job> <step> [--tail N]
tollgate run --tier T --here [--report junit] [--no-host-locks]      # CI mode
tollgate merge <branch> | pick <rev>...
tollgate config --effective | --check | init [--nextest] | ci-snippet --gitlab
tollgate policy approve <rev> [--reason S]                            # TTY only
tollgate baseline record pyright|pytest [--force]                     # TTY only
tollgate flaky [--days N] | audit [--since D] | gc [--all]
tollgate guard                                                        # PreToolUse entry (stdin JSON)
tollgate hook <name> [args]                                           # explicit dispatch
tollgate waive --tree T --tier t --reason S                           # TTY only (Q6)
```

---

## 5. Crate layout and dependencies

One binary crate `tollgate` (edition 2024, `rust-version = "1.89"`; both machines run 1.96). Modules:

| Module | Holds |
|---|---|
| `main.rs` | `catch_unwind`, argv[0] dispatch, clap CLI, exit-code mapping |
| `hook/` | `pre_commit`, `pre_merge_commit`, `pre_push`, `reference_transaction`, `chain`, `decide` (R10-R22) |
| `ledger` | tips, pending markers, sequences, reflog notes, approved policies (R29, R30, R18, R19, R68) |
| `policy` | policy files, base derivation, union rule (R66-R71) |
| `gitx` | `git` wrapper with scrubbed env and `GIT_NO_REPLACE_OBJECTS=1`; config-file parser for R7 |
| `config` | repo and host config, detection, validation (R63-R65, R84) |
| `select/` | `changed`, `rust` (`cargo_metadata` + `guppy`), `ts`, `py`, docs-only (R55-R62) |
| `steps/` | `cargo_fmt`, `cargo_clippy`, `nextest` (filterset, tool config, JUnit via `quick-xml`), `cargo_doctest`, `biome`, `tsc`, `svelte_check`, `bun_test`, `ruff`, `pyright_baseline`, `pytest_baseline`, `command` |
| `runner` | jobs, detach, built env (R52), process groups, subreaper, timeouts, verify checkout, setup |
| `sched` | queue, waiters, supersession, cancel (R89) |
| `locks` | slot semaphores with flock tickets (R85, R86) |
| `procs` | process-tree walk, parent command lookup (Linux `/proc`, macOS libproc) (R13, R35, R39) |
| `cache` | key, fingerprint, toolcache, records, gc, audit (R74-R83) |
| `report` | human and JSON reports, flaky log (R91-R93) |
| `guard` | self-check, normalization, deny/ask rules, `updatedInput` (R23-R28) |
| `install` | settings.json edit with markers, copy and links, doctor (R95-R97) |

Dependencies (crates.io, checked 2026-11-05):

| Crate | Version | Updated | Use |
|---|---|---|---|
| clap (derive) | 4.6.7 | 2026-09-14 | CLI |
| serde / serde_json (`preserve_order`) | 1.0.229 / 1.0.154 | 2026-07 / 2026-10-11 | config, records, hook JSON, settings edit |
| toml | 1.2.0 | 2026-11-04 | config files |
| anyhow / thiserror | 1.0.104 / 2.0.21 | 2026-07 / 2026-09 | errors |
| cargo_metadata | 0.23.1 | 2025-11-12 | workspace metadata |
| guppy | 0.19.1 | 2026-09-24 | reverse deps incl. dev-deps |
| globset | 0.4.21 | 2026-10-27 | globs |
| blake3 | 1.8.7 | 2026-08-20 | keys, policy sets, repo key |
| libc | 0.2.191 | 2026-10-16 | setsid, prctl, killpg |
| libproc | 0.15.0 | 2026-11-04 | macOS process tree and parent command (`procs`) |
| jiff | 0.2.39 | 2026-11-02 | timestamps, durations, dates |
| quick-xml (serde) | 0.42.0 | 2026-08-22 | JUnit |
| camino | 1.2.6 | 2026-09-15 | UTF-8 paths |
| dev: tempfile, assert_cmd | 3.27.0, 2.2.2 | 2026-03, 2026-05 | tests |

Not used: `fs4` (std `File::lock`), `determinator` (D7), `gix`/`git2` (D3), `nix` (libc suffices), `sysinfo` (libproc and `/proc` suffice), tokio.

---

## 6. Test plan

All tests create real git repos under `tempfile`, run the real `git` with `GIT_CONFIG_COUNT/KEY_0/VALUE_0` pointing at a test hooks dir of hard links to the built `tollgate`, and a test state dir via `XDG_STATE_HOME`. No mocks. Rust steps use a scratch workspace generated in the test (two path crates, one dev-dep edge, one failing test, one flaky test with a counter file). Each test names its requirements.

Trigger, scope, chaining:
- T1 (R3, manual): inside a Claude session, main and a subagent Bash call run `tollgate doctor --injection`; both report the injection.
- T2 (R1, R2, R9): a plain commit fires every installed hook through hard links; `reference-transaction` exits 0 with no subprocess in non-prepared states (strace count on Linux).
- T3 (R7): repo with `core.hooksPath=.githooks`; both hooks run; the repo hook's non-zero exit aborts.
- T4 (R4, R5): a clone renamed under `/tmp` is out of scope but its push to a `scope.remotes` URL is gated; a test suite that commits in temp repos under the injection creates no job (R52 scrub inside jobs; `$TMPDIR` exclusion for agent-run tests).
- T5 (R24): missing hooks dir, dangling link, link to another inode, wrong env value: the guard denies every Bash call; after `tollgate install` it allows.

Decision rules:
- T6 (R11, R14, R17, R18): on `main` with no record: `commit` is gated `fast` (marker) and passes; `merge --ff-only feat`, `merge --no-ff`, `branch -f main`, `reset --hard feat`, `fetch . feat:main`, `update-ref` are denied without a `full` record and allowed with one; `update-ref refs/remotes/x/y <c>` then `branch -f main <c>` is denied.
- T7 (R11c, R30): `branch -c src tmp && branch -M tmp main` with `main` not checked out is denied on the files backend; on `--ref-format=reftable` the move succeeds and the next hook reports `moved`; `branch -m` on a fast ref is allowed.
- T8 (R14(2)): a bare "remote" repo with `main` advanced; `pull --ff-only` on local `main` is allowed via `ls-remote`; the same commit made locally (not on the remote) is denied.
- T9 (R16): on a fast ref: `pull`, `checkout -b x origin/x`, `rebase --abort`, `am --abort`, `reset --hard` to an allowed reflog entry are allowed; `update-ref ORIG_HEAD <c>; reset --hard ORIG_HEAD` is denied.
- T10 (R10): `symbolic-ref refs/heads/alias refs/heads/src` is denied; `clone` and `checkout` are allowed.
- T11 (R12): `git replace E G` then a commit or push of `E` checks `E`'s real tree; `refs/replace` update is denied.
- T12 (R19): `cherry-pick a b c` on a fast ref: two intermediate allows, one gated final update with base = pre-sequence tip; the same on `main` is denied at the first pick with the `tollgate pick` message; `am` of three patches behaves the same; a three-commit rebase is gated once with the pre-rebase base.
- T13 (R20, R22): push `feat` to a trusted remote needs `full`; `fast` suffices for `wip/*`; `push origin v1` (tag) and `push --delete` pass; `push origin feat:main` needs `full`.
- T14 (R17): partial commit `git commit <path>` in a linked worktree with other staged files and an unstaged edit: record tree equals the commit tree; the agent's index and lock files are byte-identical before and after a slow job (R52).

Guard:
- T15 (R23, R25): JSON fixtures for every deny pattern, including `core.hookspath`, `include.path`, `--config-env`, `send-pack`, `branch -M x main`, `tollgate waive`, `tee > ~/.local/state/tollgate/...`: exit 2; `grep FAIL ~/.local/state/tollgate/jobs/J/tests.log` is allowed; malformed JSON and a forced panic exit 2.
- T16 (R26): `git config core.hooksPath`, Write to `tollgate.toml`, `.config/nextest.toml`, `settings.json`, `rm .git/index.lock` -> `ask`; Write under the state dir -> deny.
- T17 (R28): a `git commit` Bash input gets `timeout: 600000` and the `TOLLGATE_INLINE_CAP` prefix; a `ls` input is untouched.

Fail closed:
- T18 (R31, R37): SIGTERM and SIGKILL of tollgate during `pre-commit`: no commit; no `pass` record.
- T19 (R32, R38): step `sleep 20`, inline 2 s: deny in about 2 s naming the job; the job finishes; the retry is a cache hit.
- T20 (R33, R35): a step spawns a child that ignores SIGTERM and a grandchild via `setsid`; the limit expires; all three are gone after grace; verdict `timeout`.
- T21 (R34): `fail` denies without re-running until `--rerun`; `timeout` denies inside 15 min and re-runs after; a `deferred` disk cause writes no record.
- T22 (R39): a lock held by a live git (sleeping hook) is not reported; a 3-minute-old orphan lock is reported by `doctor`; no hook output contains `rm`.

Verify checkout and job env:
- T23 (R41, R42): checkout registered and locked; unborn repo works; `write-tree` equals `T`; ignored `target/` survives; an untracked file from the previous job is gone; a step that edits a tracked file makes `error`.
- T24 (R43): second job compiles only the changed crate and its dependent.
- T25 (R45, R46): a TS root with no `node_modules` gets `bun install --frozen-lockfile` by detection; `node_modules/.bin/biome` is used; a Python root gets `uv sync --frozen`.
- T26 (R52): a step running `env` shows no `GIT_*`, no agent-shell variable, and the allowlist only; a step that runs `git commit` in a temp repo is not gated.
- T27 (R47): `run --here` writes `report.json`, exits 0/1, and holds a `pg` slot while running.
- T28 (R44): free space below `min_free` (tmpfs of fixed size) defers the job.

Tiers, selection, policy:
- T29 (R27, R53): `full_refs` globs case-insensitive; `fast` lookup accepts `full`; `full` rejects `fast`.
- T30 (R55-R57): change in crate `a` selects `rdeps(a)` incl. the dev-dependent; `Cargo.lock` change selects the workspace; a path under no package selects the workspace; an unknown owner package selects the workspace with a WARN; an untrusted base selects the workspace; an empty diff is not docs-only.
- T31 (R58): filtersets checked with `cargo nextest list -E`; `--no-tests pass` present; doctests run.
- T32 (R61): a `.png` under `tests/fixtures` is not docs-only; a root `README.md` is; a `prompts/*.md` with `select.global` is not.
- T33 (R66-R68): a commit that deletes the `nextest` step still runs it (base policy); a commit that adds a `[[quarantine]]` for its own broken test fails `full`; after `tollgate policy approve` at a pty (test uses a pty via `openpty`) the own policy applies; approve without a TTY exits non-zero; a second commit on top of an unapproved policy change still uses the base policy.
- T34 (R69, R64): `until` 31 days after the policy commit is a config error; an unknown quarantine test is a config error.
- T35 (R79, R80): a fast record from a one-crate diff does not hit for a two-crate diff of the same tree; a `selection: all` record hits.

Cache and concurrency:
- T36 (R74): a different `rustc -vV` (shim), a different job env entry, a different `checks_schema` each give a different key; a shim with a changed mtime invalidates the toolcache.
- T37 (R81): deleting a job's `report.json` invalidates its `pass`.
- T38 (R85, R86): 6 processes compete for `cpu = 2`: at most 2 hold slots; ticket order; a SIGKILLed waiter whose pid is reused by a sleeper does not block others; two steps with `["cpu","pg"]` and `["pg","cpu"]` do not deadlock.
- T39 (R88, R89): two hooks on one tree share one job; a queued job with no waiter is superseded by a newer job from the same worktree and ref; `tollgate cancel` kills a running job and writes no record.

Reporting and flaky:
- T40 (R91, R92): failing nextest report lists the failing test, rerun command and `tollgate log` line; <= 80 lines; `tollgate log` prints the step log.
- T41 (R93): flaky test passes `fast` and is logged; fails `full`; passes `full` with a valid quarantine; fails with an expired one.
- T42 (R94): baseline kinds reproduce the shell scripts on fixtures; `record` refuses without a TTY and on a dirty tree.

Install:
- T43 (R95, R96): install on a fixture `settings.json` adds the tagged entries; an edit made after install survives `uninstall`; a second `install` after replacing the PATH binary refreshes the copy and links (inode check).
- T44 (R30): after a reftable rename of `main`, `tollgate status` shows `moved`; a `full` pass of the tip clears it.
- T45 (macOS, manual): T2, T6, T7, T12, T19, T38 on the Mac; `MAIN` vs `main` denial on APFS (R11e); record git version.

---

## 7. Open questions for Victor

Q1. Branch names that require `full` on merge and local update beyond `main` (`integration/*`, `release/*`, the batch integration branch).
Q2. Pushes to GitLab need `full` for every branch (handoff rule). Which branch globs, if any, may push with `fast` (`push.fast_refs`, for example `wip/*`)?
Q3. Fast-tier test mode default: `rdeps-unit+changed-integration` or `rdeps-all`?
Q4. Flaky policy as in R93, `retries = 2`?
Q5. Disk: two verify checkouts per repo clone (fast and full), each with its own `target/`. myapp: about 2 x 20 GB. `verify.root` on `/mnt/data1`? Same on the Mac? OK to change `scripts/cargo-guard.sh` to know that root?
Q6. Ship `tollgate waive` (TTY-only, logged) or no override at all?
Q7. Gate tags? (Proposed: no.)
Q8. Rebase: gate only the final tip (proposed) or every replayed commit via `rebase --exec tollgate check --wait`?
Q9. Import CI `full` passes as local records later (GitLab artifact -> `tollgate import`)? Not needed for v1: R14(2) trusts the remote tip.
Q10. Python: pytest in `fast` (as today) or `full` only?
Q11. Is `~/.claude/settings.json` shared between the two machines? If yes, the guard denies all Bash on the machine whose `$HOME` differs until `tollgate install` runs there; `install` would then need a machine-neutral path (symlink `/usr/local/share/tollgate` with sudo) or a SessionStart `CLAUDE_ENV_FILE` route.
Q12. tollgate repo: GitLab `victorkwak/tollgate` private, installed with `cargo install --git`? Release flow like baton?
Q13. GitLab: protect `main` on myapp, baton, wikiknit (no direct push, merge through MR, pipelines must succeed) and give `doctor` a `glab` token to check it? Resource slot values for the Arch box (`cpu = 2`, `pg = 1`, `pg_max_threads = 8`) and the Mac?
Q14. Accept that the guard denies every Bash call while the gate is not armed (R24), instead of only git commands?
Q15. Policy approval flow (R66-R68): agents' edits to `tollgate.toml` take effect only after `tollgate policy approve` at your terminal or after they land on a protected branch. Acceptable?

---

## 8. Research conflicts and unverified items

| Item | Status | Choice |
|---|---|---|
| Claude `env` block reaches every Bash and subagent call | UNVERIFIED | Primary; guard self-check (R24) fails closed; fallback `updatedInput` exports |
| `onFailure: block` on exit 1 / 101 | UNVERIFIED | Guard exits only 0 or 2 |
| `updatedInput` may change Bash `timeout` | UNVERIFIED | Default inline 100 s works without it |
| `CLAUDECODE` vs `CLAUDE_CODE_CHILD_SESSION` for scope | Verified | Neither used; the injection is the scope (R8) |
| determinator base-graph behavior | Open | Deferred (D7) |
| nextest test groups, slow/global timeout, `--config-file` | `--config-file`, `--tool-config-file`, `--no-tests`, `--flaky-result` verified in `--help` 0.9.150; timeouts from docs | Used; T20, T31 |
| nextest setup scripts | Verified experimental | Not used |
| GitLab protected-branch API via `glab` | UNVERIFIED | `doctor` warns and skips when unavailable |
| macOS: libproc, APFS case folding, flock, setsid | Not tested | POSIX only; T45 manual before `include = ["*"]` there |
| reftable repos | Rename runs no hook (verified) | Ledger report (R30), guard deny (R25), push gate (R20) |
| Parent-command lookup for `refs/remotes` (R13) | Not tested | Best effort; deny list only |
| `git commit` backgrounded by Claude at the Bash timeout | Documented | Guard raises timeout (R28); inline default under 120 s |

---

## Appendix A. Critique log

Numbering: "old" = draft 1 requirement numbers that the critique cites; "new" = this draft.

| # | Lens | Old req | Issue (short) | Resolution (new req) |
|---|---|---|---|---|
| 1 | bypass, correctness | R5, R6b, R7 | `branch -m/-M/-c/-C` moves a branch without showing the value; no hook on reftable | Full ref `0 0` line denied (R11c); guard denies rename/copy onto full refs (R25) and asks otherwise (R26); ledger `moved` report at every hook, status and audit (R29, R30); hard gate stays at push and merge by tree record (D4, R14, R20). Not a hard deny of unrelated commits: Victor's own terminal commits on `main` would otherwise block agents. Tests T7, T44. |
| 2 | bypass, correctness | R6d-f, R9, R30 | Reachability exemptions ignore tier; remotes, `ORIG_HEAD` and reflog are writable | Full refs: only a `full` record or the trusted remote's tip via `ls-remote` (R14). Fast refs: exemptions kept but limited to fetched remote refs (reflog message) and allowed reflog notes; `ORIG_HEAD` dropped (R16). `refs/remotes` writes by `update-ref`/`branch` denied best effort (R13) and by the guard (R25). `pre-push` uses no exemptions (R20). Tests T6, T8, T9. |
| 3 | bypass | R1, R2, R58c, R60, Q11 | Missing hooks path or dangling link fails open silently | Private binary copy plus hard links (R1); guard self-check of env, hooks dir and inodes on every Bash call, deny all until fixed (R24); `install.json` records the expected values; Q11, Q14. Test T5. |
| 4 | bypass, correctness | R20, R24, R16 | Job inherits `GIT_INDEX_FILE`, `GIT_DIR`, the injection and agent env | `env_clear` plus allowlist; no `GIT_*` in jobs; explicit `GIT_DIR`/`GIT_INDEX_FILE` for verify-checkout git; hook scrubs index vars for unrelated git calls (R52); env hashed into the key (R74). Tests T14, T26. |
| 5 | bypass | R38, R42, R56, R57 | Policy read from the tree it judges | Policy from a trusted base commit anchored on protected remote refs; union rule for unapproved changes; TTY-only approval; guard asks on policy edits; quarantine cap 30 days; baseline record TTY-only (D5, R49, R66-R71, R94). Tests T33, T34. |
| 6 | bypass | R11a, R2 | Guard misses lowercase `-c`, `include.path`, `--config-env`, env loss paths | Normalized matching with the verified spellings (R25); README states env loss is best effort; GitLab protection and `doctor` check (R97, Q13); `moved` report (R30). Test T15. |
| 7 | bypass | R7, R9, D3 | `refs/replace` changes the checked tree | `GIT_NO_REPLACE_OBJECTS=1` on every call; `refs/replace` updates denied; guard denies `git replace` (R12). Test T11. |
| 8 | bypass | R9, R62 | `send-pack` skips `pre-push` | Guard denies `send-pack`, `receive-pack`, `push -n/--no-verify` (R25); GitLab protection mandatory (Q13, R97). |
| 9 | bypass, correctness | R12, R49, R61 | Scope by basename; `*` gates temp repos; injection reaches tests | Scope by realpath roots and remote URLs with cache and `$TMPDIR` exclusions (R4); push to trusted remotes always gated (R5); jobs scrub the injection (R52). Test T4. |
| 10 | bypass | R30, R9, R62 | Handoff (push of a feature branch) needs only fast | Push to trusted remotes needs `full` unless `push.fast_refs` matches (R20); Q2. Test T13. |
| 11 | bypass, correctness | R10, R33 | Cherry-pick and am update the branch per commit, no pre-commit | R10 corrected (R19): fast refs defer to the final update with the saved sequence base; full refs deny with `tollgate pick` (R99). Test T12. |
| 12 | bypass, correctness | R43-R45 | Key lacks job env and tollgate version | Fingerprint adds tollgate version, `checks_schema`, built env hash, container image ids (R74). Test T36. |
| 13 | bypass, correctness | R14, R15, R21, R62 | Inline 300 s > Bash default 120 s; `rm` of live locks | Inline default 100 s; guard raises the Bash timeout to 600 s and caps inline at 540 s (R28, R33); stale locks reported only by `doctor` with ownership test, never `rm` (R39); guard asks on `rm .git/*.lock` (R26). Tests T17, T22. |
| 14 | bypass, correctness | R15, R26, R51, R18 | One checkout serializes fast behind full; queue time counted; timeouts cached | Separate fast and full checkouts (R41); `queue` budget with no record; job limit from first step; `timeout`/`error` short TTL, infrastructure causes write no record (R33, R34). Test T21. |
| 15 | bypass, correctness | R50, R19 | pid-liveness tickets break on pid reuse; cross-resource deadlock | Tickets held under `flock`, liveness = lock held (R86); canonical order, all-or-nothing (R85). Test T38. |
| 16 | bypass | R30 (macOS) | Case-insensitive refs | Case-insensitive `full_refs` match; deny case-only variants of existing branches (R11e, R27). Test T45. |
| 17 | bypass minor | R11b, R47, R63 | Guard misses host config, state dir, `.git/config`; waive by text only | Ask/deny lists extended (R26); writes to state dir denied, reads allowed (R25); waive, approve and record are TTY-only (R68, R94, R100). |
| 18 | bypass minor, correctness | R40, R34, R38 | Docs-only skips embedded files; wrong crate names in the example | Docs-only limited to paths outside code roots and select rules, never under tests/fixtures/src/prompts/migrations; repo opt-in globs (R61); example uses `gatehouse-*`; unknown owners warn and run everything (R57b, R64). Tests T30, T32. |
| 19 | bypass minor | R29, R46, R63 | Log retention invalidates records; waive has no job dir | `report.json` and `junit.xml` kept as long as the record; waive gets a synthetic job dir (R48, R82, R83). |
| 20 | bypass minor, correctness | R5, R7 | Symref values and zero-oid length | `ref:` values denied on branches; hash-length aware; name rule before value parse (R10). Test T10. |
| 21 | bypass minor, correctness | R24, R27 | Untracked files survive `read-tree` | `git clean -ffdx -e <cache dirs>`; empty `status` before and after (R42). Test T23. |
| 22 | bypass minor, correctness | R33, R43 | Fast record reused for a larger diff; empty diff counts as docs-only | Records store selection; superset rule (R79, R80); untrusted base or empty diff runs everything (R56). Tests T30, T35. |
| 23 | correctness | R21 | Live locks reported as stale | R39 (see 13). |
| 24 | correctness | R43 | Fingerprint runs `uv run`/`bunx` in the agent's checkout | Hook runs only `git` (R51); fingerprint covers PATH tools only, cached by realpath/mtime (R74, R75). |
| 25 | correctness | R26, R52, R14 | Jobs never cancelled; 12 worktrees on one slot | Waiter locks, supersession, priorities, `cancel` (R89); per-tier checkouts (R41). Test T39. |
| 26 | correctness | R39, R36 | Detection has no setup steps; `bunx` downloads | Detection adds `bun install --frozen-lockfile` and `uv sync --frozen`; tools from `node_modules/.bin` and `uv run --no-sync` (R45, R46). Test T25. |
| 27 | correctness | R23, R25, R26, R61 | No disk budget | `verify.root`, `min_free`, `max_target`, defer without record; cargo-guard change (R44, Q5). Test T28. |
| 28 | correctness | R28, R41, R53 | CI mode skips host slots | `run --here` takes slots by default; `--no-host-locks` for hosted runners (R47). Test T27. |
| 29 | correctness | R60, T32 | Uninstall restores an old backup | Marker-based removal of exactly the added entries, `preserve_order`, backup as fallback only (R96). Test T43. |
| 30 | correctness | R11a vs R54, R59 | Guard denies reading logs and the T1 command | Reads allowed, writes denied (R25); `tollgate log` (R92); `doctor --injection` carries no `hooksPath` text (R97). Test T15. |
| 31 | correctness minor | R23 | `worktree add ... HEAD` fails in an unborn repo | `--no-checkout` with an empty-tree commit anchor (R41). Test T23. |
| 32 | correctness minor | R1, R3 | Every hook name installed; subprocess per call | Hook subset (R2); config parsed without subprocess; no subprocess in non-prepared states (R7, R9). Test T2. |
| 33 | correctness minor | R15, R16 | Process-group kill misses nextest children and orphans | Subreaper, SIGTERM first with 60 s grace for nextest, descendant walk, slot released after the set is gone (R35). Test T20. |
| 34 | correctness minor | R9 vs D4 | `pre-push` gated tags | Tags and non-branch refs allowed in `pre-push` (R20, R22). Test T13. |
| 35 | correctness minor | R8, R30 | Commits directly on `main` need full inline | Commits are `fast` everywhere; full at merge, ff/reset/branch -f of full refs, and push (R17, R18, R14, R20). Test T6. |

Issues not changed, with evidence: none of the critique's critical or major issues was found wrong. One nuance: issue 1's proposed "tamper marker that denies every later hook" was weakened to a report (R30) because Victor's terminal commits on `main` are not gated by design and would trigger it; the hard guarantee moves to R14 and R20, which gate by tree record and are not affected by how the local tip moved.