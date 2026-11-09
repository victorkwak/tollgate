# Benchmark

Requirement ids (`R<n>`, `L<n>`) point into [spec.md](spec.md).

`tollgate bench` replays commits concurrently from N worktrees of one repo through the real hooks, and reports what the gate costs. Use it to choose the resource slots before a rollout (R98 step 3, and step 3 of the [rollout plan](operations.md#rollout)).

```sh
tollgate bench ~/Repos/myapp --scenarios bench.toml -n 6 --rounds 2 \
  --cpu 3 --pg 2 --pg-max-threads 12 --base-config ~/.config/tollgate/config.toml \
  --scratch /path/to/fast/disk --pg-url postgres://... --out bench.json
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
- At the end it cancels the jobs that still run, waits for their runners to exit (up to the largest step `grace` plus 15 s, so a runner ends its own steps), kills what is left (the bench's processes, and any process whose working dir or `TMPDIR` lies under the scratch dir), and removes the scratch dir (`--keep` keeps it). SIGINT or SIGTERM stops the run early; the cleanup still runs.

The report (text, or JSON with `--json`; `--out FILE` also writes the JSON) gives:

- `pre-commit` latency from hook start to allow (p50, p95, max), from git's own trace2 timing of the hook process, for all commits, cache hits, job runs, docs-only commits, per scenario and per round. The hook's own git calls also write trace events: on a 31 ms cache-hit `pre-commit` this added about 3 ms (2026-11-05), so the numbers are a little high, never low. Chained hooks that run no git are not affected.
- The other hooks' times, the `git commit` wall time, and the denied commits.
- Queue wait per resource (each step's wait for its slots, R85) and for the verify checkout (R87), and the fast job overhead beyond the steps (L19).
- Step reuse (L16), cache hits, the L19 budgets that the run measured, CPU load samples (load average; on Linux also the busy share), and with `--pg-url` the peak client connections of that Postgres (`psql` every `--sample-ms`).

Exit 0 when every commit got a gate decision; 1 when one did not (the repo was out of scope, or there was nothing to commit) or a signal stopped the run; 2 when the bench could not run. With `--enforce-budgets`, exit 1 also when a measured L19 budget is over (wall-clock p95), and stderr names it. This is where the L19 wall-clock budgets are enforced: the L19 tests assert CPU time, because a gate verdict must not depend on how busy the host is. A budget the run did not measure (for example docs-only, with no docs scenario) is not checked.
