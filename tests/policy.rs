//! L2, R49, R71: the policy commit is the merge-base with the protected
//! anchor, and a branch's own policy changes do not apply to it.

mod support;

use std::path::{Path, PathBuf};

use support::Sandbox;
use tollgate::config::RepoConfig;
use tollgate::gitx::Git;
use tollgate::policy::{self, ConfigSource};

const MAIN_POLICY: &str =
    "version = 1\n[[step]]\nname = \"tests\"\nkind = \"command\"\nrun = \"true\"\n";
const WEAK_POLICY: &str = "version = 1\n";

fn rev(sb: &Sandbox, repo: &Path, r: &str) -> tollgate::gitx::Oid {
    tollgate::gitx::Oid::parse(&sb.git(repo, &["rev-parse", r])).unwrap()
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
    let p = policy::resolve(&git, &entries, Some(&tip), &[]).unwrap();
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
    let p = policy::resolve(&git, &entries, Some(&tip), &[]).unwrap();
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
    let p = policy::resolve(&git, &entries, Some(&tip), &["origin".to_owned()]).unwrap();
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
    let p = policy::resolve(&git, &entries, Some(&tip), &["origin".to_owned()]).unwrap();
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
    let p = policy::resolve(&git, &entries, None, &[]).unwrap();
    assert_eq!(p.base.commit, None);
    assert_eq!(p.source, ConfigSource::Detected);
    assert_eq!(p.config.steps.len(), 4, "detected Rust steps");
    assert_eq!(
        p.config.effective_hash(),
        tollgate::select::detect::detected_config(&tollgate::select::detect::roots_from_tree(
            &entries
        ))
        .0
        .effective_hash()
    );
    sb.git(&repo, &["commit", "-q", "--no-verify", "-m", "c"]);
    let tip = rev(&sb, &repo, "HEAD");
    let p = policy::resolve(&git, &entries, Some(&tip), &[]).unwrap();
    assert_eq!(p.base.commit.as_ref(), Some(&tip), "no full ref: N itself");
    let _ = RepoConfig::default();
}
