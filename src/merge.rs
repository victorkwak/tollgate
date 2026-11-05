//! `tollgate merge <branch>` (R99): `git merge --no-ff --no-commit`, a
//! `full` check of the merged index tree, then `git commit --no-edit`.
//!
//! The merge and the commit run with tollgate's own environment, so the
//! commit goes through the gate hooks like any other: its `pre-commit`
//! (merge in progress, so tier by target ref) finds the record this command
//! waited for. Outcomes:
//!
//! - pass: the merge commit is made; exit as `git commit`.
//! - fail: the report, then `git merge --abort`; exit 1.
//! - still running at `TOLLGATE_INLINE_CAP`: the merge stays in progress
//!   and the command `tollgate wait <job> && git commit --no-edit` is
//!   printed; exit 3.
//! - merge conflicts: git's message; resolve, then `git commit` (gated by
//!   `pre-commit`); exit 1.

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::cache::store::Lookup;
use crate::cli::Ctx;
use crate::config::{HostConfig, Tier};
use crate::dirs::Dirs;
use crate::exit;
use crate::gitx::{Git, RepoLayout};
use crate::locks::Priority;
use crate::plan::{self, Base, PlanRequest, Settled, Started};
use crate::report::{self, JobReport};

fn fail(msg: impl std::fmt::Display) -> u8 {
    eprintln!("tollgate merge: {msg}");
    exit::BLOCK
}

/// git with tollgate's own environment (the hooks run), stdin closed.
fn git_plain(ctx: &Ctx, dir: &Path) -> Command {
    let mut cmd = Command::new(crate::gitx::program());
    cmd.env_clear();
    for (k, v) in ctx.env.iter() {
        cmd.env(k, v);
    }
    // Item 39: the recorded git, never one from GIT_EXEC_PATH.
    cmd.env_remove("GIT_EXEC_PATH")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("-C")
        .arg(dir)
        .stdin(Stdio::null());
    cmd
}

fn run_git(ctx: &Ctx, dir: &Path, args: &[&str]) -> Result<i32, String> {
    let status = git_plain(ctx, dir)
        .args(args)
        .status()
        .map_err(|e| format!("cannot run git: {e}"))?;
    Ok(status.code().unwrap_or(1))
}

fn print_report(r: &JobReport) {
    let head = format!(
        "tollgate merge: {} tree {} tier {} job {}",
        r.verdict_text().to_uppercase(),
        r.tree.short(12),
        r.tier,
        r.job_id
    );
    for l in report::render(r, &head) {
        eprintln!("{l}");
    }
}

/// `tollgate merge <branch>`.
pub fn merge(ctx: &Ctx, branch: &str) -> u8 {
    let dirs = match Dirs::from_env(&ctx.env) {
        Ok(d) => d,
        Err(e) => return fail(e),
    };
    let host = match HostConfig::load(&dirs) {
        Ok(h) => h,
        Err(e) => return fail(e),
    };
    let layout = match RepoLayout::discover(&Git::scrubbed(&ctx.env, &ctx.cwd)) {
        Ok(l) => l,
        Err(e) => return fail(format!("not in a git repository: {e}")),
    };
    let Some(worktree) = layout.worktree.clone() else {
        return fail("a bare repository has no work tree to merge in");
    };
    let git = Git::scrubbed(&ctx.env, &worktree);
    if layout.git_dir.join("MERGE_HEAD").exists() {
        return fail(
            "a merge is already in progress; finish it with git commit or git merge --abort",
        );
    }
    let before = git.rev_parse_verify("HEAD^{commit}").ok().flatten();
    match run_git(
        ctx,
        &worktree,
        &["merge", "--no-ff", "--no-commit", "--", branch],
    ) {
        Ok(0) => {}
        Ok(_) => {
            eprintln!(
                "tollgate merge: git merge stopped; resolve the conflicts, then git commit (gated by pre-commit, tier by target ref)"
            );
            return exit::FAIL;
        }
        Err(e) => return fail(e),
    }
    if !layout.git_dir.join("MERGE_HEAD").exists() {
        // "Already up to date": nothing to merge.
        return exit::OK;
    }
    let tree = match git.write_tree() {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let refname = git
        .run_line(["symbolic-ref", "-q", "HEAD"])
        .unwrap_or_else(|_| "HEAD".to_owned());
    let base = match &before {
        Some(c) => match git.tree_of(c.as_str()) {
            Ok(Some(t)) => Some(Base {
                tree: t,
                commit: Some(c.clone()),
            }),
            _ => None,
        },
        None => None,
    };
    let planned = plan::plan(&PlanRequest {
        env: &ctx.env,
        dirs: &dirs,
        host: &host,
        layout: &layout,
        git: &git,
        tree,
        tier: Tier::Full,
        tip: before,
        base,
        refname,
        allow_reuse: true,
        priority: Priority::Hook,
        rerun: false,
    });
    let p = match planned {
        Ok(p) => p,
        Err(e) => {
            let _ = run_git(ctx, &worktree, &["merge", "--abort"]);
            return fail(e);
        }
    };
    // `check --wait` semantics: up to TOLLGATE_INLINE_CAP when set (the
    // guard sets it for agents, R28), else until the job ends.
    let deadline = ctx
        .env
        .get_str("TOLLGATE_INLINE_CAP")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|s| Instant::now() + Duration::from_secs(s));
    let settled = match plan::lookup(&dirs, &p) {
        Ok(Lookup::Miss) => match plan::start(&dirs, &p, &ctx.exe, &ctx.env) {
            Ok(started) => {
                let mut say = |s: &Started| match s {
                    Started::Created(id) => {
                        eprintln!(
                            "tollgate merge: job {id} started: tier full tree {}",
                            p.spec.tree.short(12)
                        );
                    }
                    Started::Attached(id) => {
                        eprintln!("tollgate merge: attached to running job {id}")
                    }
                    Started::Hit(_) => {}
                };
                say(&started);
                plan::settle(&dirs, &p, &ctx.exe, &ctx.env, started, deadline, &mut say)
            }
            Err(e) => Err(e),
        },
        Ok(found) => Ok(Settled::Record(Box::new(found))),
        Err(e) => Err(e.into()),
    };
    let passed = match settled {
        Ok(Settled::Record(found)) => match *found {
            Lookup::Pass(_) => true,
            Lookup::Fail(r) | Lookup::Environmental(r) => {
                match JobReport::read(&dirs, &r.job_id) {
                    Ok(Some(rep)) => print_report(&rep),
                    _ => eprintln!("tollgate merge: stored {:?} (job {})", r.verdict, r.job_id),
                }
                false
            }
            Lookup::Miss => false,
        },
        Ok(Settled::Report(r)) => {
            if !r.passed() {
                print_report(&r);
            }
            r.passed()
        }
        Ok(Settled::Running(id)) => {
            eprintln!(
                "tollgate merge: job {id} is still running; the merge stays in progress. When it passes: tollgate wait {id} && git commit --no-edit"
            );
            return exit::RUNNING;
        }
        Ok(Settled::Lost(m)) => {
            eprintln!("tollgate merge: {m}");
            false
        }
        Err(e) => {
            eprintln!("tollgate merge: {e}");
            false
        }
    };
    if !passed {
        let _ = run_git(ctx, &worktree, &["merge", "--abort"]);
        eprintln!("tollgate merge: the full check did not pass; the merge is aborted");
        return exit::FAIL;
    }
    match run_git(ctx, &worktree, &["commit", "--no-edit"]) {
        Ok(code) => u8::try_from(code).unwrap_or(exit::FAIL),
        Err(e) => fail(e),
    }
}
