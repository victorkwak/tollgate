# Changelog

Versions follow the package version in `Cargo.toml`. A git tag `v<version>` marks each one. `tollgate --version` also prints the commit of the build.

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
