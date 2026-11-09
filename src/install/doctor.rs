//! `tollgate doctor [--repo P] [--injection]` (R39, R90, R97).
//!
//! One line per check: `ok`, `warn` or `FAIL`. Exit 0 when no check
//! fails. Docker is asked only for resources whose host config names an
//! image; GitLab only for `--repo` remotes that match `scope.remotes`, and
//! only through `glab` when it is installed.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use super::{InstallRecord, MIN_CLAUDE, bad_links, claude_version, settings, settings_path};
use crate::cache::toolcache::which;
use crate::cli::Ctx;
use crate::config::host::JobConfig;
use crate::config::{CompiledScope, HostConfig, Tier};
use crate::dirs::{self, Dirs};
use crate::env::EnvSnapshot;
use crate::exit;
use crate::gitx::lockfiles::{git_running_in, old_locks};
use crate::gitx::{Git, RepoLayout};
use crate::ids::ResourceName;
use crate::runner::env::{BaseInputs, JobEnv};

/// Options.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `--repo P`: stale locks, verify checkouts, GitLab protection.
    pub repo: Option<PathBuf>,
    /// `--injection`: the injection as this process sees it.
    pub injection: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Ok,
    Warn,
    Fail,
}

struct Out {
    failed: bool,
}

impl Out {
    fn line(&mut self, level: Level, what: &str, text: impl std::fmt::Display) {
        let tag = match level {
            Level::Ok => "ok  ",
            Level::Warn => "warn",
            Level::Fail => {
                self.failed = true;
                "FAIL"
            }
        };
        println!("{tag} {what}: {text}");
    }
}

fn version_of(program: &Path, args: &[&str], env: &EnvSnapshot) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    for (k, v) in env.iter() {
        cmd.env(k, v);
    }
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().next()?.trim().to_owned();
    (out.status.success() && !line.is_empty()).then_some(line)
}

fn human(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "K", "M", "G", "T"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1}{}", UNITS[u])
}

fn check_install(out: &mut Out, ctx: &Ctx, dirs: &Dirs) -> Option<InstallRecord> {
    let rec = match InstallRecord::read(dirs) {
        Ok(r) => r,
        Err(e) => {
            out.line(
                Level::Fail,
                "install",
                format!("{e}; run: tollgate install"),
            );
            return None;
        }
    };
    // R8: hooks use the recorded dirs; they must be this environment's.
    match rec.dirs_mismatch(dirs) {
        Some(why) => out.line(Level::Fail, "dirs", format!("{why}; run: tollgate install")),
        None => out.line(
            Level::Ok,
            "dirs",
            format!(
                "hooks use the recorded state dir {} and host config {}",
                dirs.state_dir().display(),
                dirs.host_config_file().display()
            ),
        ),
    }
    // Binaries (R97): the PATH binary against the installed copy.
    let installed = super::inode(&rec.binary);
    match &installed {
        Some(_) => {
            let v = version_of(&rec.binary, &["--version"], &ctx.env).unwrap_or_else(|| "?".into());
            out.line(
                Level::Ok,
                "binary",
                format!("installed copy {} ({v})", rec.binary.display()),
            );
        }
        None => out.line(
            Level::Fail,
            "binary",
            format!("{} is missing; run: tollgate install", rec.binary.display()),
        ),
    }
    match which("tollgate", ctx.env.get("PATH")) {
        Some(p) => {
            let v = version_of(&p, &["--version"], &ctx.env).unwrap_or_else(|| "?".into());
            let same = std::fs::read(&p).ok() == std::fs::read(&rec.binary).ok();
            if same {
                out.line(
                    Level::Ok,
                    "binary",
                    format!("PATH {} ({v}) is the installed build", p.display()),
                );
            } else {
                out.line(
                    Level::Warn,
                    "binary",
                    format!("PATH {} ({v}) differs from the installed copy; run tollgate install to refresh it", p.display()),
                );
            }
        }
        None => out.line(Level::Warn, "binary", "no tollgate on PATH"),
    }
    let bad = bad_links(&rec.hooks_dir, &rec.binary, &rec.hooks);
    if bad.is_empty() {
        out.line(
            Level::Ok,
            "hooks",
            format!(
                "{} links in {} share the installed copy's inode",
                rec.hooks.len(),
                rec.hooks_dir.display()
            ),
        );
    } else {
        out.line(
            Level::Fail,
            "hooks",
            format!(
                "missing or not linked to the installed copy: {}; run: tollgate install",
                bad.join(", ")
            ),
        );
    }
    Some(rec)
}

fn check_settings(out: &mut Out, ctx: &Ctx, dirs: &Dirs, rec: &InstallRecord) {
    let path = rec
        .settings
        .as_ref()
        .map_or_else(|| settings_path(&ctx.env, dirs), |s| s.path.clone());
    let command = settings::guard_command(&rec.binary);
    match std::fs::read_to_string(&path)
        .map_err(|e| e.to_string())
        .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).map_err(|e| e.to_string()))
    {
        Ok(v) => {
            let (env_ok, guards) = settings::installed_entries(&v, &rec.env, &command);
            if env_ok && guards == settings::GUARD_MATCHERS.len() {
                out.line(
                    Level::Ok,
                    "settings",
                    format!("{}: injection and {guards} guard entries", path.display()),
                );
            } else {
                out.line(
                    Level::Fail,
                    "settings",
                    format!(
                        "{}: injection {}, {guards} of {} guard entries; run tollgate install in your terminal",
                        path.display(),
                        if env_ok { "present" } else { "missing or different" },
                        settings::GUARD_MATCHERS.len()
                    ),
                );
            }
            let old = v
                .get("hooks")
                .and_then(|h| h.get("PreToolUse"))
                .is_some_and(|g| g.to_string().contains(settings::OLD_HOOK));
            if old {
                out.line(
                    Level::Warn,
                    "settings",
                    format!("{} is still registered", settings::OLD_HOOK),
                );
            }
        }
        Err(e) => out.line(Level::Fail, "settings", format!("{}: {e}", path.display())),
    }
    match claude_version(&ctx.env) {
        Ok((text, v)) if v >= MIN_CLAUDE => out.line(Level::Ok, "claude", text),
        Ok((text, _)) => out.line(
            Level::Fail,
            "claude",
            format!(
                "{text} is older than {}.{}.{} (onFailure: block, R23)",
                MIN_CLAUDE.0, MIN_CLAUDE.1, MIN_CLAUDE.2
            ),
        ),
        Err(e) => out.line(Level::Warn, "claude", e),
    }
}

/// `--injection` (R97): the text never names the config key itself, so the
/// command and its output pass the guard's text rules.
fn check_injection(out: &mut Out, ctx: &Ctx, rec: Option<&InstallRecord>) {
    let Some(rec) = rec else {
        out.line(
            Level::Fail,
            "injection",
            "no install record to compare with",
        );
        return;
    };
    let wrong: Vec<&String> = rec
        .env
        .iter()
        .filter(|(k, v)| ctx.env.get_str(k) != Some(v.as_str()))
        .map(|(k, _)| k)
        .collect();
    if wrong.is_empty() {
        out.line(
            Level::Ok,
            "injection",
            format!(
                "this process has the hook injection for {}",
                rec.hooks_dir.display()
            ),
        );
    } else {
        let names: Vec<String> = wrong
            .iter()
            .map(|k| k.to_lowercase().replace("git_config_", "slot "))
            .collect();
        out.line(
            Level::Fail,
            "injection",
            format!(
                "this process lacks the hook injection ({} missing or different)",
                names.join(", ")
            ),
        );
    }
}

/// The git `install.json` records, which hooks, jobs and the CLI run by
/// its absolute path (item 39); the step tools on the job `PATH` (R52),
/// which is what steps get. A tool only this process can find is a warning
/// that names the `[job] path_prepend` fix (R46, R97).
fn check_tools(out: &mut Out, ctx: &Ctx, dirs: &Dirs, job: &JobConfig) {
    let path = ctx.env.get("PATH");
    let found = |p: &Path, args: &[&str]| {
        let v = version_of(p, args, &ctx.env).unwrap_or_else(|| "no version".into());
        format!("{v} ({})", p.display())
    };
    match InstallRecord::read(dirs).ok().map(|r| r.git) {
        Some(Some(git)) => match version_of(&git, &["--version"], &ctx.env) {
            Some(v) if v.starts_with("git version") => {
                out.line(Level::Ok, "git", format!("{v} ({})", git.display()));
            }
            _ => out.line(
                Level::Fail,
                "git",
                format!(
                    "{} (recorded in install.json) does not run; run: tollgate install",
                    git.display()
                ),
            ),
        },
        Some(None) => out.line(
            Level::Fail,
            "git",
            "install.json records no git (an older install); run: tollgate install",
        ),
        None => match crate::gitx::find_git(&[]) {
            Some(p) => out.line(Level::Ok, "git", found(&p, &["--version"])),
            None => out.line(Level::Fail, "git", "no git in the system dirs"),
        },
    }
    let job_env = JobEnv::base(&BaseInputs {
        env: &ctx.env,
        dirs,
        job,
        tmpdir: &dirs.jobs_dir(),
    });
    let job_path = match &job_env {
        Ok(e) => e.get("PATH"),
        Err(e) => {
            out.line(Level::Fail, "job PATH", e);
            return;
        }
    };
    for (name, args) in [
        ("cargo-nextest", &["nextest", "--version"][..]),
        ("bun", &["--version"][..]),
        ("uv", &["--version"][..]),
    ] {
        match (which(name, job_path), which(name, path)) {
            (Some(p), _) => out.line(Level::Ok, name, found(&p, args)),
            (None, Some(p)) => out.line(
                Level::Warn,
                name,
                format!(
                    "{} is on this PATH but not on the job PATH (R52); add {} to [job] path_prepend",
                    p.display(),
                    p.parent().unwrap_or(&p).display()
                ),
            ),
            (None, None) => out.line(Level::Warn, name, "not on the job PATH"),
        }
    }
}

fn check_host(out: &mut Out, ctx: &Ctx, dirs: &Dirs) -> Option<HostConfig> {
    let host = match HostConfig::load(dirs) {
        Ok(h) => h,
        Err(e) => {
            out.line(Level::Fail, "host config", e);
            return None;
        }
    };
    let v = host.config.validate();
    if v.is_ok() {
        out.line(
            Level::Ok,
            "host config",
            if host.exists {
                host.path.display().to_string()
            } else {
                format!("{} absent: defaults", host.path.display())
            },
        );
    } else {
        let errs: Vec<String> = v.errors.iter().map(ToString::to_string).collect();
        out.line(Level::Fail, "host config", errs.join("; "));
    }
    for w in &v.warnings {
        out.line(Level::Warn, "host config", w);
    }
    // R90: the bound on test-Postgres connections.
    let pg = ResourceName::parse("pg").ok();
    if let Some(pg) = &pg {
        let slots = host.config.resource_slots(pg);
        let threads = host.config.nextest.pg_max_threads;
        let bound = u64::from(slots) * u64::from(threads) * 6;
        let image = host.config.resource_image(pg).map(str::to_owned);
        let max = image.as_deref().and_then(|i| pg_max_connections(ctx, i));
        match max {
            Some(m) if m < bound => out.line(
                Level::Fail,
                "pg",
                format!("bound {slots} slots x {threads} threads x 6 = {bound} > max_connections {m} (R90)"),
            ),
            Some(m) => out.line(Level::Ok, "pg", format!("bound {bound} <= max_connections {m} (R90)")),
            None => out.line(
                Level::Ok,
                "pg",
                format!("bound {slots} slots x {threads} threads x 6 = {bound} connections (R90){}", if image.is_some() { "; container max_connections unknown" } else { "" }),
            ),
        }
    }
    // Writable dirs.
    for (name, dir) in [
        ("state", dirs.state_dir()),
        ("data", dirs.data_dir()),
        ("config", dirs.config_dir()),
    ] {
        let probe = dir.join(format!(".doctor-{}", crate::fsx::unique_suffix()));
        let ok = crate::fsx::ensure_dir(&dir).is_ok() && std::fs::write(&probe, b"").is_ok();
        let _ = std::fs::remove_file(&probe);
        if ok {
            out.line(
                Level::Ok,
                "dirs",
                format!("{name} {} writable", dir.display()),
            );
        } else {
            out.line(
                Level::Fail,
                "dirs",
                format!("{name} {} not writable", dir.display()),
            );
        }
    }
    let root = host.config.verify.root(dirs);
    let existing = root.ancestors().find(|a| a.exists()).unwrap_or(&root);
    match crate::runner::checkout::free_bytes(existing) {
        Ok(free) => {
            let min = host.config.verify.min_free.bytes();
            let level = if free < min { Level::Fail } else { Level::Ok };
            out.line(
                level,
                "disk",
                format!(
                    "verify root {}: {} free (min_free {})",
                    root.display(),
                    human(free),
                    human(min)
                ),
            );
        }
        Err(e) => out.line(
            Level::Warn,
            "disk",
            format!("verify root {}: {e}", root.display()),
        ),
    }
    Some(host.config)
}

/// The test Postgres container's `max_connections` (R90), when docker
/// runs a container of `image`.
fn pg_max_connections(ctx: &Ctx, image: &str) -> Option<u64> {
    let docker = which("docker", ctx.env.get("PATH"))?;
    let run = |args: &[&str]| -> Option<String> {
        let out = Command::new(&docker)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    let names = run(&[
        "ps",
        "--filter",
        &format!("ancestor={image}"),
        "--format",
        "{{.Names}}",
    ])?;
    let name = names.lines().next()?;
    run(&[
        "exec",
        name,
        "psql",
        "-U",
        "postgres",
        "-tAc",
        "show max_connections",
    ])?
    .trim()
    .parse()
    .ok()
}

fn check_repo(out: &mut Out, ctx: &Ctx, dirs: &Dirs, host: Option<&HostConfig>, repo: &Path) {
    let git = Git::scrubbed(&ctx.env, repo);
    let layout = match RepoLayout::discover(&git) {
        Ok(l) => l,
        Err(e) => {
            out.line(Level::Fail, "repo", format!("{}: {e}", repo.display()));
            return;
        }
    };
    // R39: stale locks only when no live git works in the repo.
    let mut work_dirs = vec![layout.common_dir.clone()];
    if let Ok(list) = git.run_line(["worktree", "list", "--porcelain"]) {
        work_dirs.extend(
            list.lines()
                .filter_map(|l| l.strip_prefix("worktree "))
                .filter_map(|p| std::fs::canonicalize(p).ok()),
        );
    }
    let locks = old_locks(&layout.common_dir, Duration::from_secs(120));
    if locks.is_empty() {
        out.line(Level::Ok, "locks", "no git lock file older than 2 minutes");
    } else {
        match git_running_in(&work_dirs) {
            Some(true) => out.line(
                Level::Warn,
                "locks",
                format!("{} lock file(s) older than 2 minutes, but a git process works in this repo: not stale", locks.len()),
            ),
            Some(false) => {
                for l in &locks {
                    out.line(
                        Level::Fail,
                        "locks",
                        format!("stale: {} ({} min old, no git process works in the repo)", l.path.display(), l.age.as_secs() / 60),
                    );
                }
            }
            None => {
                for l in &locks {
                    out.line(
                        Level::Warn,
                        "locks",
                        format!("{} is {} min old; owner check not available here", l.path.display(), l.age.as_secs() / 60),
                    );
                }
            }
        }
    }
    // Verify checkouts of this repo (L15).
    if let Some(host) = host {
        let root = host.verify.root(dirs);
        let registered = git
            .run_line(["worktree", "list", "--porcelain"])
            .unwrap_or_default();
        for tier in [Tier::Fast, Tier::Full] {
            let tdir = dirs::verify_tier_dir(&root, &layout.repo_key(), tier);
            let Ok(rd) = std::fs::read_dir(&tdir) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if !p.is_dir() {
                    continue;
                }
                let size = crate::runner::checkout::dir_size(&p);
                let known = registered.lines().any(|l| {
                    l.strip_prefix("worktree ")
                        .is_some_and(|w| Path::new(w) == p)
                });
                let level = if known { Level::Ok } else { Level::Warn };
                out.line(
                    level,
                    "checkout",
                    format!(
                        "{tier} {} {}{}",
                        p.display(),
                        human(size),
                        if known {
                            ""
                        } else {
                            " (not registered; gc removes it)"
                        }
                    ),
                );
            }
        }
        // R97: GitLab protection of main per trusted remote.
        if let Ok(scope) = CompiledScope::new(&host.scope, dirs) {
            // Item 48: trusted paths count only in their canonical spelling.
            for (entry, canonical) in scope.noncanonical_trusted_paths() {
                out.line(
                    Level::Warn,
                    "scope",
                    format!(
                        "scope.trusted_paths entry {entry} is not its canonical path; it trusts nothing. Write {} (item 48)",
                        canonical.display()
                    ),
                );
            }
            for r in crate::plan::remote_urls(&git).unwrap_or_default() {
                let respelled = r
                    .fetch
                    .first()
                    .and_then(|u| scope.trusted_path_respelled(u).map(|c| (u, c)));
                if let Some((url, canonical)) = respelled {
                    out.line(
                        Level::Warn,
                        "remotes",
                        format!(
                            "remote {}: {url} reaches the trusted path {} by another spelling (a symlink, `..` or a trailing /), so it is not trusted (item 48); use the canonical path: git remote set-url {} {}",
                            r.name,
                            canonical.display(),
                            r.name,
                            canonical.display()
                        ),
                    );
                }
            }
            let names = match crate::plan::trusted_remotes(&git, &scope) {
                Ok(n) => n,
                Err(e) => {
                    out.line(Level::Fail, "remotes", e.to_string());
                    return;
                }
            };
            if names.is_empty() {
                out.line(
                    Level::Warn,
                    "remotes",
                    "no trusted remote (scope.remotes names none by its exact host and path, scope.trusted_paths none by its path): policy comes from the local main, a commit whose base has no record runs every step, and a push runs the branch's own tier",
                );
            } else {
                out.line(
                    Level::Ok,
                    "remotes",
                    format!("trusted: {}", names.join(", ")),
                );
            }
            for name in names {
                let url = git
                    .run_line(["remote", "get-url", &name])
                    .unwrap_or_default();
                gitlab_protection(out, ctx, &name, &url);
            }
        }
    }
}

/// The GitLab project path of a remote URL (`group/proj`).
fn gitlab_project(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("git@gitlab.com:")
        .or_else(|| url.strip_prefix("ssh://git@gitlab.com/"))
        .or_else(|| url.strip_prefix("https://gitlab.com/"))?;
    let path = rest.trim_end_matches('/');
    Some(path.strip_suffix(".git").unwrap_or(path).to_owned())
}

fn gitlab_protection(out: &mut Out, ctx: &Ctx, name: &str, url: &str) {
    let Some(project) = gitlab_project(url) else {
        out.line(
            Level::Warn,
            "gitlab",
            format!("remote {name}: not a gitlab.com URL; protection not checked"),
        );
        return;
    };
    let Some(glab) = which("glab", ctx.env.get("PATH")) else {
        out.line(
            Level::Warn,
            "gitlab",
            format!("{project}: glab is not installed; protection of main not checked"),
        );
        return;
    };
    let enc = project.replace('/', "%2F");
    let res = Command::new(glab)
        .args(["api", &format!("projects/{enc}/protected_branches")])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let Some(res) = res.ok().filter(|o| o.status.success()) else {
        out.line(
            Level::Warn,
            "gitlab",
            format!("{project}: glab api failed; protection not checked"),
        );
        return;
    };
    let v: serde_json::Value = serde_json::from_slice(&res.stdout).unwrap_or_default();
    let protected = v.as_array().is_some_and(|a| {
        a.iter()
            .any(|b| b.get("name").and_then(serde_json::Value::as_str) == Some("main"))
    });
    if protected {
        out.line(Level::Ok, "gitlab", format!("{project}: main is protected"));
    } else {
        out.line(
            Level::Fail,
            "gitlab",
            format!("{project}: main is not protected (Q13, R97)"),
        );
    }
}

/// `tollgate doctor`.
pub fn doctor(ctx: &Ctx, opts: &Options) -> u8 {
    let mut out = Out { failed: false };
    let dirs = match Dirs::from_env(&ctx.env) {
        Ok(d) => d,
        Err(e) => {
            out.line(Level::Fail, "dirs", e);
            return exit::FAIL;
        }
    };
    let rec = check_install(&mut out, ctx, &dirs);
    if let Some(rec) = &rec {
        check_settings(&mut out, ctx, &dirs, rec);
    }
    if opts.injection {
        check_injection(&mut out, ctx, rec.as_ref());
    }
    let host = check_host(&mut out, ctx, &dirs);
    let job = host.as_ref().map(|h| h.job.clone()).unwrap_or_default();
    check_tools(&mut out, ctx, &dirs, &job);
    if let Some(repo) = &opts.repo {
        let repo = if repo.is_absolute() {
            repo.clone()
        } else {
            ctx.cwd.join(repo)
        };
        check_repo(&mut out, ctx, &dirs, host.as_ref(), &repo);
    }
    if out.failed { exit::FAIL } else { exit::OK }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitlab_project_paths_r97() {
        assert_eq!(
            gitlab_project("git@gitlab.com:victorkwak/myapp.git").as_deref(),
            Some("victorkwak/myapp")
        );
        assert_eq!(gitlab_project("/srv/x.git"), None);
    }
}
