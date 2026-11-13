# Changelog

Versions follow the package version in `Cargo.toml`. A git tag `v<version>` marks each one. `tollgate --version` also prints the commit of the build.

## 0.3.1 (2026-11-13)

A fix for verify checkouts that filled the disk, and a Mac fix for the R112 tests. This version voids no stored result.

Fixed:

- Verify checkouts of agent worktrees that are gone no longer stay until the count limit. `tollgate gc` removes them, and a job below `verify.min_free` removes them (and those of gone repos) before it defers. Before, a checkout was removed only when its whole repo was gone or the LRU limit of 12 was passed, so the checkouts of removed worktrees filled the disk and the gate deferred every job while it held them (L15, R44, R48).
- The R112 tests read process state from `/proc`, which macOS does not have: every process read as gone, so one test failed on the Mac and the others checked nothing there. They read the process table now.

## 0.3.0 (2026-11-13)

More guards against wasted runs (spec section 4.14, R110 to R113). This version voids no stored result.

Changed behavior:

- One commit in the gate for each full-tier ref. `pre-push` refuses a second commit for a ref that already has one in the gate, before any job, unless the second commit contains the first. Host config `[push] second_candidate = "allow"` turns this off (R111).
- A newer push from the same worktree and branch (an amended commit) replaces its own earlier commit in the gate and cancels that job (R111).
- For a job that `pre-push` created, a watcher process beside the runner (`tollgate __watch-push`) asks the trusted server for the ref during the run (`[push] remote_check`, default `2m`). The job ends as cancelled, with a reason, when the ref moved past its commit. A job that `check`, `merge`, `run` or a forced push also waits for is never ended (R112).
- The fingerprint entry `tollgate` is a record epoch (`0.2.0`), not the package version. A new version number alone no longer voids the stored results; `checks_schema` does that for a release that changes what a pass means (R110).
- `tollgate install` says whether the new build reads the stored results, and asks before it voids the results of jobs that are queued or running (R110).

Added:

- A bare number is seconds for a duration flag: `tollgate wait <job> --timeout 3000` (R113).
- `tollgate status` lists the commits in the gate for each ref (R111).

A host config with a `[push]` table is refused by 0.2.0 and older. Add the table only on a machine that runs 0.3.0, and remove it before a rollback.

## 0.2.0 (2026-11-12)

Guards against wasted test runs (spec section 4.14) and a version that names its build.

Changed behavior:

- A push of a branch to a trusted remote needs the `fast` tier. The `full` tier is for full refs (`tiers.full_refs`) and for branches that match the new `push.full_refs`. `push.fast_refs` still parses and has no effect (R107).
- In a Claude Code session, `tollgate check --tier full` creates no job. Host config `[session] full_check = "allow"` turns this off (R104).
- The fingerprint holds what a job reads from `tollgate.toml`, not the hash of the file. This voids the stored results one time for each repo that has the file (R74). The new version number voids them one time for every repo.

Added:

- A step that ran and passed on the same tree is not run again, also for a full ref. `tollgate check --rerun` runs only the steps that did not pass; `--rerun --all` runs every step (R101).
- `pre-push` refuses a push that the remote would reject as not a fast-forward, before any job (R102).
- `[[expensive]]` in `tollgate.toml`: the guard refuses the wide form of a declared command and prints the narrow form (R103).
- `tollgate run <step>`: one stored result per step and inputs, with its log and artefacts (R105). Step field `artifacts` (R106).
- A new branch is compared with its policy commit, not with the empty tree (R108).
- `tollgate cost`: gate time per day, repo and tier (R109).
- `tollgate --version` and `tollgate doctor` print the git commit of the build, for example `tollgate 0.2.0 (a1b2c3d4e5f6)`.

An older binary refuses a `tollgate.toml` that has `[[expensive]]`, `push.full_refs` or a step with `artifacts`. Install 0.2.0 on every machine before such a file reaches `main`.

## 0.1.0 (2026-11-06)

First version on crates.io.
