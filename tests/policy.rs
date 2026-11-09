//! L2, R49, R71: the policy commit is the merge-base with the protected
//! anchor, and a branch's own policy changes do not apply to it.

mod support;

use std::path::{Path, PathBuf};

use support::Sandbox;
use tollgate::config::RepoConfig;
use tollgate::gitx::Git;
use tollgate::policy::{self, ConfigSource};
use tollgate::remote_refs::{RemoteRefs, TrustedRemote};

const MAIN_POLICY: &str =
    "version = 1\n[[step]]\nname = \"tests\"\nkind = \"command\"\nrun = \"true\"\n";
const WEAK_POLICY: &str = "version = 1\n";

fn rev(sb: &Sandbox, repo: &Path, r: &str) -> tollgate::gitx::Oid {
    tollgate::gitx::Oid::parse(&sb.git(repo, &["rev-parse", r])).unwrap()
}

/// `origin` at `url` as the one trusted remote.
fn trusted(sb: &Sandbox, url: &Path) -> RemoteRefs {
    let env = sb.env();
    RemoteRefs::new(
        &tollgate::dirs::Dirs::from_env(&env).unwrap(),
        &env,
        &[],
        vec![TrustedRemote {
            name: "origin".into(),
            url: url.to_str().unwrap().to_owned(),
        }],
    )
}

/// A bare repo at `<root>/<name>` as `origin` of `repo`.
fn bare_origin(sb: &Sandbox, repo: &Path, name: &str) -> PathBuf {
    let bare = sb.root().join(name);
    std::fs::create_dir_all(&bare).unwrap();
    sb.git(&bare, &["init", "-q", "--bare"]);
    sb.git(repo, &["remote", "add", "origin", bare.to_str().unwrap()]);
    bare
}

#[test]
fn branch_policy_changes_wait_for_the_merge_l2() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    sb.commit_file(&repo, "tollgate.toml", MAIN_POLICY, "policy");
    sb.commit_file(
        &repo,
        ".config/nextest.toml",
        "[profile.default]\nretries = 1\n",
        "nextest",
    );
    let main_tip = rev(&sb, &repo, "HEAD");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "weaken");
    sb.commit_file(&repo, "src.txt", "x", "work");
    let tip = rev(&sb, &repo, "HEAD");

    let git = Git::scrubbed(&sb.env(), &repo);
    let tree = git.tree_of("HEAD").unwrap().unwrap();
    let entries = git.ls_tree(&tree).unwrap();
    let p = policy::resolve(
        &git,
        &entries,
        Some(&tip),
        &RemoteRefs::none(),
        Some("refs/heads/feat"),
    )
    .unwrap();
    assert_eq!(
        p.base.commit.as_ref(),
        Some(&main_tip),
        "merge-base with local main"
    );
    assert_eq!(p.base.anchor.as_deref(), Some("refs/heads/main"));
    assert_eq!(p.config.steps.len(), 1, "main's policy applies");
    assert!(matches!(p.source, ConfigSource::File { .. }));
    assert_eq!(p.changed, [PathBuf::from("tollgate.toml")]);
    let line = p.line().unwrap();
    assert!(
        line.starts_with("POLICY: this branch changes tollgate.toml; checks use the policy of ")
            && line.ends_with("until it merges to main"),
        "{line}"
    );
    assert_eq!(
        p.nextest_configs.get(Path::new("")).map(String::as_str),
        Some("[profile.default]\nretries = 1\n")
    );
    let committed = p.base.committer_date.unwrap();
    assert_eq!(committed, jiff::Zoned::now().date());

    // After the merge, the policy is the merged one.
    sb.git(&repo, &["checkout", "-q", "main"]);
    sb.git(&repo, &["merge", "-q", "--no-verify", "--ff-only", "feat"]);
    let tip = rev(&sb, &repo, "HEAD");
    let p = policy::resolve(
        &git,
        &entries,
        Some(&tip),
        &RemoteRefs::none(),
        Some("refs/heads/main"),
    )
    .unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&tip));
    assert!(p.config.steps.is_empty());
    assert!(p.line().is_none());
    assert_ne!(p.files_hash(), "");
}

#[test]
fn trusted_remote_full_refs_anchor_first_l2() {
    let sb = Sandbox::new();
    // The "remote" URL must match a scope.remotes glob: its path names it.
    let remote = sb.root().join("gitlab.com/victorkwak/r.git");
    std::fs::create_dir_all(&remote).unwrap();
    sb.git(&remote, &["init", "-q", "--bare"]);
    let repo = sb.repo("r");
    sb.commit_file(&repo, "tollgate.toml", MAIN_POLICY, "policy");
    sb.git(
        &repo,
        &["remote", "add", "origin", remote.to_str().unwrap()],
    );
    sb.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let remote_main = rev(&sb, &repo, "origin/main");
    // Local main moves ahead with a weaker policy; the remote anchor wins.
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "local weaken");
    let tip = rev(&sb, &repo, "HEAD");
    let git = Git::scrubbed(&sb.env(), &repo);
    let entries = git.ls_tree(&git.tree_of("HEAD").unwrap().unwrap()).unwrap();
    let p = policy::resolve(
        &git,
        &entries,
        Some(&tip),
        &trusted(&sb, &remote),
        Some("refs/heads/main"),
    )
    .unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&remote_main));
    assert_eq!(p.base.anchor.as_deref(), Some("refs/remotes/origin/main"));
    assert_eq!(p.config.steps.len(), 1);
    assert!(
        p.line()
            .unwrap()
            .ends_with("until it merges to origin/main")
    );

    // An unrelated history (orphan branch) gets the anchor's policy.
    sb.git(&repo, &["checkout", "-q", "--orphan", "lonely"]);
    sb.git(&repo, &["rm", "-q", "-rf", "."]);
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "orphan");
    let tip = rev(&sb, &repo, "HEAD");
    let p = policy::resolve(
        &git,
        &entries,
        Some(&tip),
        &trusted(&sb, &remote),
        Some("refs/heads/main"),
    )
    .unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&remote_main));
}

#[test]
fn no_anchor_uses_the_tip_and_unborn_uses_the_tree_l2_r65() {
    let sb = Sandbox::new();
    let repo = sb.root().join("u");
    std::fs::create_dir_all(&repo).unwrap();
    sb.git(&repo, &["init", "-q", "-b", "feat"]);
    std::fs::write(repo.join("Cargo.toml"), "[workspace]\n").unwrap();
    sb.git(&repo, &["add", "-A"]);
    let git = Git::scrubbed(&sb.env(), &repo);
    let tree = git.write_tree().unwrap();
    let entries = git.ls_tree(&tree).unwrap();
    let p = policy::resolve(
        &git,
        &entries,
        None,
        &RemoteRefs::none(),
        Some("refs/heads/feat"),
    )
    .unwrap();
    assert_eq!(p.base.commit, None);
    assert_eq!(p.source, ConfigSource::Detected);
    assert_eq!(p.config.steps.len(), 4, "detected Rust steps");
    assert_eq!(
        p.config.effective_hash(),
        tollgate::select::detect::detect_tree(&git, &entries)
            .0
            .effective_hash()
    );
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "c"]);
    let tip = rev(&sb, &repo, "HEAD");
    let p = policy::resolve(
        &git,
        &entries,
        Some(&tip),
        &RemoteRefs::none(),
        Some("refs/heads/feat"),
    )
    .unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&tip), "no anchor: N itself");
    let _ = RepoConfig::default();
}

/// A local repo with `main` holding the strong policy and a branch `feat`
/// that weakens it; returns (repo, main tip, feat tip).
fn weakened_branch(sb: &Sandbox) -> (PathBuf, tollgate::gitx::Oid, tollgate::gitx::Oid) {
    let repo = sb.repo("r");
    sb.commit_file(&repo, "tollgate.toml", MAIN_POLICY, "policy");
    let main_tip = rev(sb, &repo, "HEAD");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "weaken");
    let tip = rev(sb, &repo, "HEAD");
    (repo, main_tip, tip)
}

fn resolve_at(
    sb: &Sandbox,
    repo: &Path,
    tip: &tollgate::gitx::Oid,
    remotes: &RemoteRefs,
    own: &str,
) -> Result<policy::Policy, policy::PolicyError> {
    let git = Git::scrubbed(&sb.env(), repo);
    let entries = git
        .ls_tree(&git.tree_of(tip.as_str()).unwrap().unwrap())
        .unwrap();
    policy::resolve(&git, &entries, Some(tip), remotes, Some(own))
}

#[test]
fn a_branch_made_at_the_own_tip_does_not_anchor_l2() {
    let sb = Sandbox::new();
    let (repo, main_tip, tip) = weakened_branch(&sb);
    // integration/* is a full ref but not an anchor; a case variant of main
    // is not main.
    sb.git(&repo, &["branch", "integration/x", "HEAD"]);
    // (APFS is case-insensitive by default: there `Main` is `main`.)
    if cfg!(not(target_os = "macos")) {
        sb.git(&repo, &["branch", "Main", "HEAD"]);
    }
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
    assert_eq!(p.base.anchor.as_deref(), Some("refs/heads/main"));
    assert_eq!(p.config.steps.len(), 1, "main's policy applies");

    // `master` created at the own tip: main has priority, and one
    // merge-base per anchor (not one across all anchors).
    sb.git(&repo, &["branch", "master", "HEAD"]);
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
}

#[test]
fn a_local_anchor_that_contains_the_tip_is_skipped_l2() {
    let sb = Sandbox::new();
    let (repo, main_tip, tip) = weakened_branch(&sb);
    // The repo's anchor is `master`; the agent creates `main` at its tip.
    sb.git(&repo, &["branch", "-m", "main", "master"]);
    sb.git(&repo, &["branch", "main", "HEAD"]);
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
    assert_eq!(p.base.anchor.as_deref(), Some("refs/heads/master"));
    assert_eq!(p.config.steps.len(), 1);

    // The job's own ref is never its anchor: on `master` itself with no
    // other anchor, N itself.
    let p = resolve_at(
        &sb,
        &repo,
        &main_tip,
        &RemoteRefs::none(),
        "refs/heads/master",
    )
    .unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
}

#[test]
fn trusted_remotes_without_fetched_anchors_deny_l2() {
    let sb = Sandbox::new();
    let (repo, _, tip) = weakened_branch(&sb);
    let bare = bare_origin(&sb, &repo, "remotes/trusted.git");
    let origin = trusted(&sb, &bare);
    // Local main exists, but trusted remotes never fall back to local refs.
    let err = resolve_at(&sb, &repo, &tip, &origin, "refs/heads/feat")
        .expect_err("no fetched anchor must deny");
    assert!(
        matches!(err, policy::PolicyError::NoAnchor(_))
            && err.to_string().contains("git fetch origin"),
        "{err}"
    );
    // origin/master alone is enough; origin/main ranks first when both
    // exist.
    sb.git(&repo, &["push", "-q", "origin", "main:master"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let p = resolve_at(&sb, &repo, &tip, &origin, "refs/heads/feat").unwrap();
    assert_eq!(p.base.anchor.as_deref(), Some("refs/remotes/origin/master"));
    let root = rev(&sb, &repo, "main~1");
    sb.git(&repo, &["push", "-q", "origin", "main~1:refs/heads/main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    // A new process (each hook is one) asks the server again.
    let origin = trusted(&sb, &bare);
    let p = resolve_at(&sb, &repo, &tip, &origin, "refs/heads/feat").unwrap();
    assert_eq!(p.base.anchor.as_deref(), Some("refs/remotes/origin/main"));
    assert_eq!(p.base.commit.as_ref(), Some(&root));
}

/// L2, X1: forged remote-tracking anchors. `git fetch .`, `git fetch
/// <path>` and `git update-ref` write `refs/remotes/origin/*` (with any
/// reflog message); only the newest value the trusted server reported
/// counts, and a server that confirms nothing denies.
#[test]
fn forged_remote_tracking_anchors_are_not_trusted_l2() {
    let sb = Sandbox::new();
    let (repo, main_tip, tip) = weakened_branch(&sb);
    let bare = bare_origin(&sb, &repo, "remotes/trusted.git");
    sb.git(&repo, &["push", "-q", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let origin = trusted(&sb, &bare);
    let check = |what: &str| {
        let p = resolve_at(&sb, &repo, &tip, &origin, "refs/heads/feat").unwrap();
        assert_eq!(p.base.commit.as_ref(), Some(&main_tip), "{what}");
        assert_eq!(p.config.steps.len(), 1, "{what}: main's policy applies");
    };
    check("fetched");
    sb.git(
        &repo,
        &["fetch", "-q", ".", "+feat:refs/remotes/origin/main"],
    );
    assert_eq!(rev(&sb, &repo, "origin/main"), tip);
    check("fetch .");
    sb.git(
        &repo,
        &[
            "update-ref",
            "-m",
            "fetch origin: fast-forward",
            "refs/remotes/origin/main",
            tip.as_str(),
        ],
    );
    check("update-ref");
    // A forged origin/master, which the server does not have, is no
    // anchor either: origin/main (confirmed) ranks first anyway, and with
    // origin/main gone origin/master alone is unconfirmed: deny.
    sb.git(
        &repo,
        &["update-ref", "refs/remotes/origin/master", tip.as_str()],
    );
    check("forged master");
    sb.git(&repo, &["update-ref", "-d", "refs/remotes/origin/main"]);
    let err = resolve_at(&sb, &repo, &tip, &origin, "refs/heads/feat")
        .expect_err("an unconfirmed anchor only");
    assert!(
        matches!(err, policy::PolicyError::NoAnchor(_))
            && err.to_string().contains("confirms no value")
            && err.to_string().contains("no branch master"),
        "{err}"
    );
    // A repo that has the server's value through another fetch: a forged
    // tracking ref is ignored, the confirmed value decides.
    sb.git(&repo, &["update-ref", "-d", "refs/remotes/origin/master"]);
    sb.git(
        &repo,
        &[
            "fetch",
            "-q",
            bare.to_str().unwrap(),
            "+main:refs/remotes/origin/main",
        ],
    );
    check("refetched");
    // An unreachable server and no value it reported before: deny.
    let sb2 = Sandbox::new();
    let (repo2, _, tip2) = weakened_branch(&sb2);
    let gone = sb2.root().join("remotes/gone.git");
    sb2.git(&repo2, &["update-ref", "refs/remotes/origin/main", "main"]);
    let err = resolve_at(
        &sb2,
        &repo2,
        &tip2,
        &trusted(&sb2, &gone),
        "refs/heads/feat",
    )
    .expect_err("no server");
    assert!(err.to_string().contains("ls-remote"), "{err}");
}

#[test]
fn the_anchor_commits_config_names_the_anchors_l2() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    sb.git(&repo, &["branch", "-m", "main", "trunk"]);
    sb.commit_file(
        &repo,
        "tollgate.toml",
        &format!("{MAIN_POLICY}[policy]\nanchors = [\"trunk\"]\n"),
        "policy",
    );
    let trunk = rev(&sb, &repo, "HEAD");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "weaken");
    let tip = rev(&sb, &repo, "HEAD");
    // No default anchor exists: N itself first, whose config names no
    // other anchor (WEAK_POLICY), so the branch's own policy applies until
    // a default anchor exists.
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&tip));
    // With `main` at trunk's tip, main's config names `trunk`.
    sb.git(&repo, &["branch", "main", trunk.as_str()]);
    sb.commit_file(&repo, "x.txt", "x", "more");
    let tip = rev(&sb, &repo, "HEAD");
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&trunk));
    assert_eq!(p.config.steps.len(), 1);
}

#[test]
fn anchors_named_by_the_policy_that_do_not_exist_keep_the_first_pass_l2() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    // main's config names an anchor that no ref has; no trusted remote.
    sb.commit_file(
        &repo,
        "tollgate.toml",
        &format!("{MAIN_POLICY}[policy]\nanchors = [\"trunk\"]\n"),
        "policy",
    );
    let main_tip = rev(&sb, &repo, "HEAD");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "weaken");
    let tip = rev(&sb, &repo, "HEAD");
    // The second pass finds no anchor: the first pass (main) still
    // decides, never the branch's own tip.
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
    assert_eq!(p.base.anchor.as_deref(), Some("refs/heads/main"));
    assert_eq!(p.config.steps.len(), 1, "main's policy applies");
    assert_eq!(p.changed, [PathBuf::from("tollgate.toml")]);
}

/// Item 32 (R3): with a trusted remote, a second pass whose
/// `policy.anchors` names refs that do not exist keeps the first pass, as
/// without one. Refs that exist but that the server does not confirm
/// still deny.
#[test]
fn trusted_anchors_named_by_the_policy_that_do_not_exist_keep_the_first_pass_item32() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    sb.commit_file(
        &repo,
        "tollgate.toml",
        &format!("{MAIN_POLICY}[policy]\nanchors = [\"trunk\"]\n"),
        "policy",
    );
    let bare = bare_origin(&sb, &repo, "origin.git");
    sb.git(&repo, &["push", "-q", "--no-verify", "origin", "main"]);
    sb.git(&repo, &["fetch", "-q", "origin"]);
    let main_tip = rev(&sb, &repo, "origin/main");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(&repo, "tollgate.toml", WEAK_POLICY, "weaken");
    let tip = rev(&sb, &repo, "HEAD");
    let remotes = trusted(&sb, &bare);
    let p = resolve_at(&sb, &repo, &tip, &remotes, "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
    assert_eq!(p.base.anchor.as_deref(), Some("refs/remotes/origin/main"));
    assert_eq!(p.config.steps.len(), 1, "main's policy applies");
    // `trunk` fetched, then moved by hand to a value the server never
    // reported: it exists but is not confirmed, so the policy denies.
    sb.git(
        &repo,
        &["update-ref", "refs/remotes/origin/trunk", tip.as_str()],
    );
    let err = resolve_at(&sb, &repo, &tip, &remotes, "refs/heads/feat").unwrap_err();
    assert!(matches!(err, policy::PolicyError::NoAnchor(_)), "{err}");
}

#[test]
fn tool_configs_come_from_the_policy_commit_r71() {
    let sb = Sandbox::new();
    let repo = sb.repo("r");
    sb.commit_file(&repo, "rustfmt.toml", "max_width = 100\n", "fmt");
    let main_tip = rev(&sb, &repo, "HEAD");
    sb.git(&repo, &["checkout", "-q", "-b", "feat"]);
    sb.commit_file(
        &repo,
        "rustfmt.toml",
        "disable_all_formatting = true\n",
        "weaken",
    );
    sb.commit_file(
        &repo,
        "crates/x/clippy.toml",
        "too-many-lines-threshold = 9999\n",
        "lint",
    );
    sb.commit_file(
        &repo,
        "tools/.cargo/config.toml",
        "[alias]\nnextest = \"version\"\n",
        "alias",
    );
    sb.commit_file(&repo, "src/fine.rs", "\n", "code");
    let tip = rev(&sb, &repo, "HEAD");
    let p = resolve_at(&sb, &repo, &tip, &RemoteRefs::none(), "refs/heads/feat").unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&main_tip));
    assert_eq!(
        p.changed,
        [
            PathBuf::from("crates/x/clippy.toml"),
            PathBuf::from("rustfmt.toml"),
            PathBuf::from("tools/.cargo/config.toml"),
        ]
    );
    let got: Vec<(String, policy::OverlayFile)> = p
        .overlay
        .iter()
        .map(|(k, v)| (k.display().to_string(), v.clone()))
        .collect();
    assert_eq!(
        got,
        [
            (
                "crates/x/clippy.toml".to_owned(),
                policy::OverlayFile::Absent
            ),
            (
                "rustfmt.toml".to_owned(),
                policy::OverlayFile::File {
                    text: "max_width = 100\n".into(),
                    executable: false
                }
            ),
            (
                "tools/.cargo/config.toml".to_owned(),
                policy::OverlayFile::Absent
            ),
        ]
    );
    // On the anchor itself nothing differs.
    let p = resolve_at(
        &sb,
        &repo,
        &main_tip,
        &RemoteRefs::none(),
        "refs/heads/feat",
    )
    .unwrap();
    assert!(p.overlay.is_empty() && p.changed.is_empty());
}
