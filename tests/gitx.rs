//! gitx against real git: scrubbed env, replace objects, layout, and the R7
//! hooks path checked against git's own answer and against which hook git
//! actually runs.

mod support;

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use support::{Sandbox, norm};
use tollgate::env::EnvSnapshot;
use tollgate::gitx::hooks_path::{self, NeedsGit, RepoHooks};
use tollgate::gitx::{Git, ObjectFormat, Oid, RepoLayout};

fn layout(sb: &Sandbox, dir: &Path) -> RepoLayout {
    RepoLayout::discover(&Git::scrubbed(&sb.env(), dir)).unwrap()
}

#[test]
fn no_replace_objects_r12() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    let e = sb.commit_file(&repo, "e.txt", "E\n", "E");
    let g = sb.commit_file(&repo, "g.txt", "G\n", "G");
    sb.git(&repo, &["replace", &e, &g]);
    let replaced = sb.git(&repo, &["rev-parse", &format!("{e}^{{tree}}")]);
    let g_tree = sb.git(&repo, &["rev-parse", &format!("{g}^{{tree}}")]);
    assert_eq!(replaced, g_tree, "plain git follows the replace ref");

    let git = Git::scrubbed(&sb.env(), &repo);
    let real = git.tree_of(&e).unwrap().unwrap();
    assert_ne!(real.as_str(), g_tree, "tollgate must see E's own tree");
    let via_cat = sb.git_with(
        &repo,
        &["rev-parse", &format!("{e}^{{tree}}")],
        &[("GIT_NO_REPLACE_OBJECTS", OsStr::new("1"))],
    );
    assert_eq!(real.as_str(), via_cat);
}

#[test]
fn scrubbed_calls_ignore_inherited_dirs_index_and_injection_r52() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    let other = sb.repo("other");
    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    let hostile = sb
        .env()
        .with("GIT_DIR", other.join(".git"))
        .with("GIT_WORK_TREE", &other)
        .with("GIT_INDEX_FILE", other.join(".git/index"))
        .with("GIT_CONFIG_COUNT", "1")
        .with("GIT_CONFIG_KEY_0", "core.hooksPath")
        .with("GIT_CONFIG_VALUE_0", "/injected")
        .with("GIT_CONFIG_PARAMETERS", "'core.hookspath'='/param'");
    let git = Git::scrubbed(&hostile, &repo);
    assert_eq!(
        git.run_line(["config", "--get", "core.hooksPath"]).unwrap(),
        ".githooks"
    );
    let l = RepoLayout::discover(&git).unwrap();
    assert_eq!(l.worktree.as_deref(), Some(repo.as_path()));
    assert_eq!(
        git.write_tree().unwrap(),
        git.tree_of("HEAD").unwrap().unwrap()
    );
}

#[test]
fn with_index_file_writes_that_index_r17() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    let first_tree = sb.git(&repo, &["rev-parse", "HEAD^{tree}"]);
    sb.commit_file(&repo, "b.txt", "b\n", "b");
    let tmp_index = sb.root().join("partial-index");
    sb.git_with(
        &repo,
        &["read-tree", &first_tree],
        &[("GIT_INDEX_FILE", tmp_index.as_os_str())],
    );
    let git = Git::scrubbed(&sb.env(), &repo);
    assert_eq!(
        git.clone()
            .with_index_file(&tmp_index)
            .write_tree()
            .unwrap()
            .as_str(),
        first_tree
    );
    assert_ne!(git.write_tree().unwrap().as_str(), first_tree);
}

#[test]
fn rev_parse_helpers() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    let git = Git::scrubbed(&sb.env(), &repo);
    assert!(git.rev_parse_verify("HEAD").unwrap().is_some());
    assert_eq!(git.rev_parse_verify("refs/heads/nope").unwrap(), None);
    // An option-looking rev is a rev, not an option.
    assert_eq!(git.rev_parse_verify("--output=pwned").unwrap(), None);
    assert!(!repo.join("pwned").exists());
    assert_eq!(git.object_format().unwrap(), ObjectFormat::Sha1);
    let empty = sb.git(&repo, &["hash-object", "-t", "tree", "/dev/null"]);
    assert_eq!(ObjectFormat::Sha1.empty_tree().as_str(), empty);
}

#[test]
fn sha256_repos_r10() {
    let sb = Sandbox::new();
    let dir = sb.root().join("r256");
    std::fs::create_dir_all(&dir).unwrap();
    sb.git(&dir, &["init", "-q", "--object-format=sha256"]);
    let git = Git::scrubbed(&sb.env(), &dir);
    let fmt = git.object_format().unwrap();
    assert_eq!(fmt, ObjectFormat::Sha256);
    let empty = sb.git(&dir, &["hash-object", "-t", "tree", "/dev/null"]);
    assert_eq!(fmt.empty_tree().as_str(), empty);
    // An unborn branch has no HEAD tree (R17 uses the empty tree).
    assert_eq!(git.tree_of("HEAD").unwrap(), None);
    assert_eq!(git.write_tree().unwrap(), Oid::parse(&empty).unwrap());
}

#[test]
fn system_config_default_is_absolute() {
    let sb = Sandbox::new();
    let git = Git::scrubbed(&sb.env(), sb.root());
    let p = git.system_config_default().unwrap().expect("git >= 2.42");
    assert!(p.is_absolute(), "{}", p.display());
}

/// Installs a hook that dumps its cwd and env, runs a commit in `dir`, and
/// returns what the hook saw.
fn hook_view(sb: &Sandbox, dir: &Path, hooks: &Path) -> (PathBuf, EnvSnapshot) {
    std::fs::create_dir_all(hooks).unwrap();
    let dump = sb.root().join(format!("dump-{}", std::process::id()));
    let script = format!(
        "#!/bin/sh\npwd > '{d}.cwd'\nenv -0 > '{d}.env'\n",
        d = dump.display()
    );
    support::write_exe(&hooks.join("pre-commit"), &script);
    std::fs::write(
        dir.join("touched.txt"),
        format!("{:?}\n", std::time::SystemTime::now()),
    )
    .unwrap();
    sb.git(dir, &["add", "touched.txt"]);
    sb.git(dir, &["commit", "-q", "-m", "x"]);
    let cwd = std::fs::read_to_string(format!("{}.cwd", dump.display())).unwrap();
    let raw = std::fs::read(format!("{}.env", dump.display())).unwrap();
    let env = EnvSnapshot::from_pairs(raw.split(|b| *b == 0).filter(|kv| !kv.is_empty()).map(
        |kv| {
            let s = String::from_utf8_lossy(kv).into_owned();
            let (k, v) = s.split_once('=').unwrap();
            (k.to_owned(), v.to_owned())
        },
    ));
    (PathBuf::from(cwd.trim()), env)
}

#[test]
fn layout_from_hook_env_matches_discover() {
    let sb = Sandbox::new();
    let repo = sb.repo("main-wt");
    let linked = sb.root().join("linked");
    sb.git(
        &repo,
        &[
            "worktree",
            "add",
            "-q",
            "-b",
            "feat",
            linked.to_str().unwrap(),
        ],
    );
    let hooks = sb.root().join("hooks");
    sb.git(
        &repo,
        &["config", "core.hooksPath", hooks.to_str().unwrap()],
    );

    for dir in [&repo, &linked] {
        let (cwd, env) = hook_view(&sb, dir, &hooks);
        let from_hook = RepoLayout::for_hook(&cwd, &env).expect("readable from hook env");
        assert_eq!(from_hook, layout(&sb, dir), "{}", dir.display());
        assert_eq!(from_hook.repo_dir(), repo, "L4: the common dir decides");
        assert_eq!(from_hook.repo_key(), layout(&sb, &repo).repo_key());
    }

    let bare = sb.root().join("b.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    let l = layout(&sb, &bare);
    assert!(l.is_bare());
    assert_eq!(l.repo_dir(), bare);
    let from_hook = RepoLayout::for_hook(&bare, &EnvSnapshot::default()).unwrap();
    assert_eq!(from_hook, l);
    assert_eq!(
        RepoLayout::for_hook(&sb.root(), &EnvSnapshot::default()),
        None
    );
}

/// One R7 scenario: `parse` (files only) and `git` (fallback) must agree, and
/// both must name the dir git uses when no injection is present.
fn check_hooks(dir: &Path, env: &EnvSnapshot, want: &RepoHooks) {
    let l = RepoLayout::discover(&Git::scrubbed(env, dir)).unwrap();
    let git = Git::scrubbed(env, dir);
    let system = git.system_config_default().unwrap();
    let parsed = hooks_path::parse_hooks_path(&l, env, system.as_deref())
        .unwrap_or_else(|e| panic!("{}: parse needs git: {e}", dir.display()));
    let via_git = hooks_path::hooks_path_via_git(&git, &l).unwrap();
    let n = |h: &RepoHooks| match h {
        RepoHooks::Dir(p) => RepoHooks::Dir(norm(p)),
        RepoHooks::Disabled => RepoHooks::Disabled,
    };
    assert_eq!(n(&parsed), n(want), "parse in {}", dir.display());
    assert_eq!(n(&via_git), n(want), "git in {}", dir.display());
}

/// Runs a commit and returns true when `<hooks>/pre-commit` ran.
fn hook_ran(sb: &Sandbox, dir: &Path, hooks: &Path, extra: &[(&str, &OsStr)]) -> bool {
    std::fs::create_dir_all(hooks).unwrap();
    let marker = sb.root().join("ran");
    let _ = std::fs::remove_file(&marker);
    let hook = hooks.join("pre-commit");
    support::write_exe(&hook, &format!("#!/bin/sh\ntouch '{}'\n", marker.display()));
    std::fs::write(
        dir.join("touched.txt"),
        format!("{:?}\n", std::time::SystemTime::now()),
    )
    .unwrap();
    sb.git_with(dir, &["add", "touched.txt"], extra);
    sb.git_with(dir, &["commit", "-q", "-m", "x"], extra);
    let ran = marker.exists();
    let _ = std::fs::remove_file(&hook);
    ran
}

#[test]
fn hooks_path_default_and_local_values_r7() {
    let sb = Sandbox::new();
    let env = sb.env();
    let repo = sb.repo("r");
    let common = repo.join(".git");
    check_hooks(&repo, &env, &RepoHooks::Dir(common.join("hooks")));
    assert!(hook_ran(&sb, &repo, &common.join("hooks"), &[]));

    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    check_hooks(&repo, &env, &RepoHooks::Dir(repo.join(".githooks")));
    assert!(hook_ran(&sb, &repo, &repo.join(".githooks"), &[]));
    // From a subdirectory the relative path still resolves at the root.
    std::fs::create_dir_all(repo.join("sub")).unwrap();
    check_hooks(
        &repo.join("sub"),
        &env,
        &RepoHooks::Dir(repo.join(".githooks")),
    );

    sb.git(&repo, &["config", "core.hooksPath", "~/my hooks"]);
    check_hooks(&repo, &env, &RepoHooks::Dir(sb.home.join("my hooks")));

    sb.git(&repo, &["config", "core.hooksPath", ""]);
    check_hooks(&repo, &env, &RepoHooks::Disabled);
    assert!(!hook_ran(&sb, &repo, &common.join("hooks"), &[]));
}

#[test]
fn hooks_path_global_xdg_and_system_precedence_r7() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    let xdg = sb.root().join("config/git/config");
    std::fs::create_dir_all(xdg.parent().unwrap()).unwrap();
    std::fs::write(&xdg, "[core]\n\thooksPath = /xdg/hooks\n").unwrap();
    let env = sb.env();
    check_hooks(&repo, &env, &RepoHooks::Dir("/xdg/hooks".into()));

    // ~/.gitconfig is read after the XDG file and wins.
    let home_cfg = sb.home.join(".gitconfig");
    let mut text = std::fs::read_to_string(&home_cfg).unwrap();
    text.push_str("[core]\n\thooksPath = /home/hooks\n");
    std::fs::write(&home_cfg, &text).unwrap();
    check_hooks(&repo, &env, &RepoHooks::Dir("/home/hooks".into()));

    // GIT_CONFIG_GLOBAL replaces both global files.
    let alt = sb.root().join("alt-global");
    let alt_hooks = sb.root().join("alt-hooks");
    std::fs::write(
        &alt,
        format!(
            "[user]\n\tname = T\n\temail = t@t\n[core]\n\thooksPath = {}\n",
            alt_hooks.display()
        ),
    )
    .unwrap();
    let env_alt = env.clone().with("GIT_CONFIG_GLOBAL", &alt);
    check_hooks(&repo, &env_alt, &RepoHooks::Dir(alt_hooks.clone()));
    assert!(hook_ran(
        &sb,
        &repo,
        &alt_hooks,
        &[("GIT_CONFIG_GLOBAL", alt.as_os_str())]
    ));

    // System file through GIT_CONFIG_SYSTEM; NOSYSTEM turns it off.
    let sys = sb.root().join("system-config");
    std::fs::write(&sys, "[core]\n\thooksPath = /sys/hooks\n").unwrap();
    let env_sys = env
        .clone()
        .without("GIT_CONFIG_NOSYSTEM")
        .with("GIT_CONFIG_SYSTEM", &sys)
        .with("GIT_CONFIG_GLOBAL", "/dev/null");
    check_hooks(&repo, &env_sys, &RepoHooks::Dir("/sys/hooks".into()));
    let env_nosys = env_sys.clone().with("GIT_CONFIG_NOSYSTEM", "true");
    check_hooks(&repo, &env_nosys, &RepoHooks::Dir(repo.join(".git/hooks")));

    // Local beats global.
    sb.git(&repo, &["config", "core.hooksPath", "local-hooks"]);
    check_hooks(&repo, &env, &RepoHooks::Dir(repo.join("local-hooks")));
}

#[test]
fn hooks_path_linked_worktrees_and_worktree_config_r7() {
    let sb = Sandbox::new();
    let env = sb.env();
    let repo = sb.repo("r");
    let wt = sb.root().join("wt");
    sb.git(
        &repo,
        &["worktree", "add", "-q", "-b", "feat", wt.to_str().unwrap()],
    );
    // Default: the common dir's hooks.
    check_hooks(&wt, &env, &RepoHooks::Dir(repo.join(".git/hooks")));
    // A relative path resolves in the linked worktree's root.
    sb.git(&repo, &["config", "core.hooksPath", ".githooks"]);
    check_hooks(&wt, &env, &RepoHooks::Dir(wt.join(".githooks")));
    assert!(hook_ran(&sb, &wt, &wt.join(".githooks"), &[]));
    // Per-worktree config applies to that worktree only.
    sb.git(&repo, &["config", "extensions.worktreeConfig", "true"]);
    sb.git(&wt, &["config", "--worktree", "core.hooksPath", "wt-hooks"]);
    check_hooks(&wt, &env, &RepoHooks::Dir(wt.join("wt-hooks")));
    check_hooks(&repo, &env, &RepoHooks::Dir(repo.join(".githooks")));
}

#[test]
fn hooks_path_bare_repo_r7() {
    let sb = Sandbox::new();
    let env = sb.env();
    let bare = sb.root().join("b.git");
    sb.git(
        &sb.root(),
        &["init", "-q", "--bare", bare.to_str().unwrap()],
    );
    check_hooks(&bare, &env, &RepoHooks::Dir(bare.join("hooks")));
    sb.git(&bare, &["config", "core.hooksPath", "rel-hooks"]);
    check_hooks(&bare, &env, &RepoHooks::Dir(bare.join("rel-hooks")));
}

#[test]
fn includes_and_expansions_fall_back_to_git_r7() {
    let sb = Sandbox::new();
    let env = sb.env();
    let repo = sb.repo("r");
    let inc = sb.root().join("inc.cfg");
    std::fs::write(&inc, "[core]\n\thooksPath = /from/include\n").unwrap();
    sb.git(&repo, &["config", "include.path", inc.to_str().unwrap()]);
    let l = layout(&sb, &repo);
    let git = Git::scrubbed(&env, &repo);
    let err = hooks_path::parse_hooks_path(&l, &env, None).unwrap_err();
    assert!(matches!(err, NeedsGit::Include(_)), "{err}");
    let r = hooks_path::repo_hooks(&l, &env, None, &git).unwrap();
    assert_eq!(r.hooks, RepoHooks::Dir("/from/include".into()));
    assert!(r.asked_git.is_some());

    sb.git(&repo, &["config", "--unset", "include.path"]);
    sb.git(
        &repo,
        &["config", "core.hooksPath", "%(prefix)/share/hooks"],
    );
    let r = hooks_path::repo_hooks(&l, &env, None, &git).unwrap();
    assert!(matches!(r.asked_git, Some(NeedsGit::Value(_))));
    let RepoHooks::Dir(p) = r.hooks else {
        panic!("expected a dir")
    };
    assert!(
        p.ends_with("share/hooks") && !p.to_str().unwrap().contains("%("),
        "{}",
        p.display()
    );

    // A syntax error git also rejects is reported, not guessed.
    std::fs::write(repo.join(".git/config"), "[core\n").unwrap();
    assert!(matches!(
        hooks_path::parse_hooks_path(&l, &env, None).unwrap_err(),
        NeedsGit::Syntax { .. }
    ));
    assert!(hooks_path::repo_hooks(&l, &env, None, &git).is_err());
}

#[test]
fn quoted_values_match_git_r7() {
    let sb = Sandbox::new();
    let env = sb.env();
    let repo = sb.repo("r");
    let cfg = repo.join(".git/config");
    let mut text = std::fs::read_to_string(&cfg).unwrap();
    text.push_str("[core]\n\thooksPath = \"spaced  dir\"   ; comment\n");
    std::fs::write(&cfg, text).unwrap();
    check_hooks(&repo, &env, &RepoHooks::Dir(repo.join("spaced  dir")));
    assert!(hook_ran(&sb, &repo, &repo.join("spaced  dir"), &[]));
}
