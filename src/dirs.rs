//! The config, state and data dir layout.
//!
//! XDG base dirs on Linux and macOS alike (R1: "same layout on macOS"):
//!
//! | Dir | Default | Holds |
//! |---|---|---|
//! | `$XDG_CONFIG_HOME/tollgate/` | `~/.config/tollgate/` | `config.toml` host config (R84) |
//! | `$XDG_DATA_HOME/tollgate/` | `~/.local/share/tollgate/` | `bin/tollgate`, `hooks/<name>`, `install.json` (R1, R24) |
//! | `$XDG_STATE_HOME/tollgate/` | `~/.local/state/tollgate/` | records, jobs, locks, toolcache, flaky log, default verify root |
//!
//! State dir contents:
//!
//! - `toolcache.json` (R75)
//! - `results/<key[..2]>/<key>.json` (R76)
//! - `jobs/<job id>/` (R82): `job.json` (state), `spec.json` (the planned
//!   job), `report.json`, `<step>.log`, `<step>.junit.xml`, `setup-<name>.log`,
//!   `job.log`, `runner.log`, `runner.pid`, `tmp/` (the job's `TMPDIR`),
//!   `waiters/` (R89), `cancel`
//! - `jobs/by-key/<key>.lock` (R88), `jobs/queue/<origin>/` (R89)
//! - `locks/<resource>/slot-<i>`, `locks/<resource>/queue/` (R85, R86)
//! - `steps/<key[..2]>/<key>.json`: stored step passes (L16)
//! - `metadata/<key>.json`: workspace maps for selection without cargo
//! - `flaky.jsonl` (R93)
//! - `metrics.jsonl` (+ `.1`..`.3`), `metrics.key`, `metrics.lock`: guard,
//!   hook and job metrics for `tollgate stats` (item 50)
//! - `verify/` (default `verify.root`, R41)
//!
//! A verify root holds `<repo key>/<tier>/<worktree key>`: one sticky
//! checkout per agent worktree and tier (L15), with `<worktree key>.lock`
//! (R87) and `<worktree key>.json` (LRU metadata) beside it.
//!
//! `repairs.log` in the state dir records guard self-repairs (L18).

use std::path::{Path, PathBuf};

use crate::config::Tier;
use crate::env::EnvSnapshot;
use crate::ids::{JobId, RecordKey, RepoKey, ResourceName, StepKey, WorktreeKey};

const APP: &str = "tollgate";

/// Error when the base dirs cannot be found.
#[derive(Debug, thiserror::Error)]
pub enum DirsError {
    /// `HOME` is unset, empty or relative.
    #[error("HOME is not set to an absolute path")]
    NoHome,
}

/// The resolved base dirs. `install.json` records them, and hooks of an
/// install read them from there (R8).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Dirs {
    home: PathBuf,
    config_home: PathBuf,
    state_home: PathBuf,
    data_home: PathBuf,
}

impl Dirs {
    /// Resolves the dirs from `HOME` and the `XDG_*_HOME` variables. An XDG
    /// value that is empty or relative is ignored, as the XDG spec requires.
    pub fn from_env(env: &EnvSnapshot) -> Result<Self, DirsError> {
        let home = env
            .get_nonempty("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or(DirsError::NoHome)?;
        let xdg = |var: &str, default: &str| {
            env.get_nonempty(var)
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .unwrap_or_else(|| home.join(default))
        };
        Ok(Self {
            config_home: xdg("XDG_CONFIG_HOME", ".config"),
            state_home: xdg("XDG_STATE_HOME", ".local/state"),
            data_home: xdg("XDG_DATA_HOME", ".local/share"),
            home,
        })
    }

    /// `$HOME`.
    #[must_use]
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// `env` with `HOME` and the `XDG_*_HOME` variables set to these dirs,
    /// so git calls and the job runner a hook starts resolve the same
    /// dirs (R8).
    #[must_use]
    pub fn env_for(&self, env: &EnvSnapshot) -> EnvSnapshot {
        env.clone()
            .with("HOME", &self.home)
            .with("XDG_CONFIG_HOME", &self.config_home)
            .with("XDG_STATE_HOME", &self.state_home)
            .with("XDG_DATA_HOME", &self.data_home)
    }

    /// Expands a leading `~` or `~/` to `$HOME`. Other text is returned as is.
    #[must_use]
    pub fn expand_tilde(&self, raw: &str) -> PathBuf {
        if raw == "~" {
            self.home.clone()
        } else if let Some(rest) = raw.strip_prefix("~/") {
            self.home.join(rest)
        } else {
            PathBuf::from(raw)
        }
    }

    /// `$XDG_CONFIG_HOME/tollgate`.
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.config_home.join(APP)
    }

    /// The host config file (R84).
    #[must_use]
    pub fn host_config_file(&self) -> PathBuf {
        self.config_dir().join("config.toml")
    }

    /// `$XDG_DATA_HOME/tollgate`.
    #[must_use]
    pub fn data_dir(&self) -> PathBuf {
        self.data_home.join(APP)
    }

    /// The private copy of the binary (R1).
    #[must_use]
    pub fn installed_binary(&self) -> PathBuf {
        self.data_dir().join("bin").join(APP)
    }

    /// The injected hooks dir with one hard link per hook name (R1, R2).
    #[must_use]
    pub fn hooks_dir(&self) -> PathBuf {
        self.data_dir().join("hooks")
    }

    /// What `install` wrote, for `uninstall` and the guard self-check (R24, R96).
    #[must_use]
    pub fn install_record(&self) -> PathBuf {
        self.data_dir().join("install.json")
    }

    /// `$XDG_STATE_HOME/tollgate`.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.state_home.join(APP)
    }

    /// `$XDG_STATE_HOME/tollgate/probe`: content-addressed dirs where tool
    /// version probes run, holding a tree's toolchain files (R51, R74).
    #[must_use]
    pub fn probe_root(&self) -> PathBuf {
        self.state_dir().join("probe")
    }

    /// Gate-hook runs that allowed a commit, one marker per git process
    /// (item 17).
    #[must_use]
    pub fn gate_runs_dir(&self) -> PathBuf {
        self.state_dir().join("gate-runs")
    }

    /// Trees that passed a job or that a gate hook allowed, one empty file
    /// per tree (item 17).
    #[must_use]
    pub fn passed_trees_dir(&self) -> PathBuf {
        self.state_dir().join("trees")
    }

    /// Commits made without the gate, per repo (item 17).
    #[must_use]
    pub fn unverified_dir(&self) -> PathBuf {
        self.state_dir().join("unverified")
    }

    /// What trusted servers reported for their branches (L2, R56).
    #[must_use]
    pub fn remote_refs_file(&self) -> PathBuf {
        self.state_dir().join("remote-refs.json")
    }

    /// Tool version cache (R75).
    #[must_use]
    pub fn toolcache_file(&self) -> PathBuf {
        self.state_dir().join("toolcache.json")
    }

    /// Root of the record store (R76).
    #[must_use]
    pub fn results_dir(&self) -> PathBuf {
        self.state_dir().join("results")
    }

    /// `results/<key[..2]>/<key>.json` (R76).
    #[must_use]
    pub fn record_file(&self, key: &RecordKey) -> PathBuf {
        self.results_dir()
            .join(key.shard())
            .join(format!("{key}.json"))
    }

    /// Root of the step result store (L16).
    #[must_use]
    pub fn step_results_dir(&self) -> PathBuf {
        self.state_dir().join("steps")
    }

    /// `steps/<key[..2]>/<key>.json`: a stored step pass (L16).
    #[must_use]
    pub fn step_result_file(&self, key: &StepKey) -> PathBuf {
        self.step_results_dir()
            .join(key.shard())
            .join(format!("{key}.json"))
    }

    /// `metadata/<key>.json`: workspace maps by manifest key, written by
    /// the runner, read by front ends that run no cargo (R51).
    #[must_use]
    pub fn workspace_map_file(&self, key: &str) -> PathBuf {
        self.state_dir()
            .join("metadata")
            .join(format!("{key}.json"))
    }

    /// Root of the job dirs (R82).
    #[must_use]
    pub fn jobs_dir(&self) -> PathBuf {
        self.state_dir().join("jobs")
    }

    /// `jobs/<job id>/` (R82).
    #[must_use]
    pub fn job_dir(&self, id: &JobId) -> PathBuf {
        self.jobs_dir().join(id.as_str())
    }

    /// `jobs/<job id>/report.json`; a pass without it is invalid (R81).
    #[must_use]
    pub fn job_report(&self, id: &JobId) -> PathBuf {
        self.job_dir(id).join("report.json")
    }

    /// `jobs/by-key/<key>.lock`: held by the one job for a key (R88).
    #[must_use]
    pub fn job_dedupe_lock(&self, key: &RecordKey) -> PathBuf {
        self.jobs_dir().join("by-key").join(format!("{key}.lock"))
    }

    /// `jobs/queue/`: markers of queued jobs per origin (R89).
    #[must_use]
    pub fn job_queue_dir(&self) -> PathBuf {
        self.jobs_dir().join("queue")
    }

    /// Root of the resource semaphores (R85).
    #[must_use]
    pub fn locks_dir(&self) -> PathBuf {
        self.state_dir().join("locks")
    }

    /// `locks/<resource>/` (R85).
    #[must_use]
    pub fn resource_lock_dir(&self, resource: &ResourceName) -> PathBuf {
        self.locks_dir().join(resource.as_str())
    }

    /// Flaky test log (R93).
    #[must_use]
    pub fn flaky_log(&self) -> PathBuf {
        self.state_dir().join("flaky.jsonl")
    }

    /// The verify root when the host config sets none (R41).
    #[must_use]
    pub fn default_verify_root(&self) -> PathBuf {
        self.state_dir().join("verify")
    }

    /// One line per guard self-repair (L18).
    #[must_use]
    pub fn repairs_log(&self) -> PathBuf {
        self.state_dir().join("repairs.log")
    }

    /// The metrics log (item 50); rotated copies get `.1`, `.2`, ...
    #[must_use]
    pub fn metrics_log(&self) -> PathBuf {
        self.state_dir().join("metrics.jsonl")
    }

    /// The key of the metrics log's command hashes (item 50).
    #[must_use]
    pub fn metrics_key(&self) -> PathBuf {
        self.state_dir().join("metrics.key")
    }

    /// The lock one metrics log rotation holds (item 50).
    #[must_use]
    pub fn metrics_lock(&self) -> PathBuf {
        self.state_dir().join("metrics.lock")
    }
}

/// `<verify root>/<repo key>/<tier>/`: the checkouts of one tier.
#[must_use]
pub fn verify_tier_dir(verify_root: &Path, repo: &RepoKey, tier: Tier) -> PathBuf {
    verify_root.join(repo.as_str()).join(tier.as_str())
}

/// The sticky verify checkout of one agent worktree (L15):
/// `<verify root>/<repo key>/<tier>/<worktree key>`.
#[must_use]
pub fn verify_checkout(
    verify_root: &Path,
    repo: &RepoKey,
    tier: Tier,
    worktree: &WorktreeKey,
) -> PathBuf {
    verify_tier_dir(verify_root, repo, tier).join(worktree.as_str())
}

/// The lock held for the whole job by the job using a checkout (R87):
/// `<checkout>.lock`, next to the checkout so removing the checkout (LRU,
/// L15) never removes a held lock file.
#[must_use]
pub fn verify_checkout_lock(
    verify_root: &Path,
    repo: &RepoKey,
    tier: Tier,
    worktree: &WorktreeKey,
) -> PathBuf {
    verify_tier_dir(verify_root, repo, tier).join(format!("{worktree}.lock"))
}

/// Metadata of a checkout (origin path, last use) for LRU eviction (L15):
/// `<checkout>.json`.
#[must_use]
pub fn verify_checkout_meta(
    verify_root: &Path,
    repo: &RepoKey,
    tier: Tier,
    worktree: &WorktreeKey,
) -> PathBuf {
    verify_tier_dir(verify_root, repo, tier).join(format!("{worktree}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> EnvSnapshot {
        EnvSnapshot::from_pairs(pairs.iter().copied())
    }

    #[test]
    fn defaults_follow_home() {
        let d = Dirs::from_env(&env(&[("HOME", "/h")])).unwrap();
        assert_eq!(
            d.host_config_file(),
            PathBuf::from("/h/.config/tollgate/config.toml")
        );
        assert_eq!(d.state_dir(), PathBuf::from("/h/.local/state/tollgate"));
        assert_eq!(
            d.installed_binary(),
            PathBuf::from("/h/.local/share/tollgate/bin/tollgate")
        );
        assert_eq!(
            d.hooks_dir(),
            PathBuf::from("/h/.local/share/tollgate/hooks")
        );
        assert_eq!(
            d.default_verify_root(),
            PathBuf::from("/h/.local/state/tollgate/verify")
        );
    }

    #[test]
    fn xdg_values_override_but_relative_or_empty_ones_are_ignored() {
        let d = Dirs::from_env(&env(&[
            ("HOME", "/h"),
            ("XDG_CONFIG_HOME", "/c"),
            ("XDG_STATE_HOME", "relative/state"),
            ("XDG_DATA_HOME", ""),
        ]))
        .unwrap();
        assert_eq!(d.config_dir(), PathBuf::from("/c/tollgate"));
        assert_eq!(d.state_dir(), PathBuf::from("/h/.local/state/tollgate"));
        assert_eq!(d.data_dir(), PathBuf::from("/h/.local/share/tollgate"));
    }

    #[test]
    fn missing_or_relative_home_is_an_error() {
        assert!(Dirs::from_env(&env(&[])).is_err());
        assert!(Dirs::from_env(&env(&[("HOME", "rel")])).is_err());
    }

    #[test]
    fn record_and_job_paths_r76_r82_r88() {
        let d = Dirs::from_env(&env(&[("HOME", "/h"), ("XDG_STATE_HOME", "/s")])).unwrap();
        let key = RecordKey::parse(&format!("ab{}", "0".repeat(62))).unwrap();
        assert_eq!(
            d.record_file(&key),
            PathBuf::from(format!("/s/tollgate/results/ab/{key}.json"))
        );
        assert_eq!(
            d.job_dedupe_lock(&key),
            PathBuf::from(format!("/s/tollgate/jobs/by-key/{key}.lock"))
        );
        let job = JobId::parse("20261105-010203-0123abcd").unwrap();
        assert_eq!(
            d.job_report(&job),
            PathBuf::from("/s/tollgate/jobs/20261105-010203-0123abcd/report.json")
        );
        let pg = ResourceName::parse("pg").unwrap();
        assert_eq!(
            d.resource_lock_dir(&pg),
            PathBuf::from("/s/tollgate/locks/pg")
        );
    }

    #[test]
    fn sticky_verify_checkouts_l15_r87() {
        let repo = RepoKey::parse("0123456789abcdef").unwrap();
        let wt = WorktreeKey::of_realpath(Path::new("/home/u/Repos/myapp-fix-8"));
        let root = Path::new("/v");
        let base = format!("/v/0123456789abcdef/fast/{wt}");
        assert_eq!(
            verify_checkout(root, &repo, Tier::Fast, &wt),
            PathBuf::from(&base)
        );
        assert_eq!(
            verify_checkout_lock(root, &repo, Tier::Fast, &wt),
            PathBuf::from(format!("{base}.lock"))
        );
        assert_eq!(
            verify_checkout_meta(root, &repo, Tier::Fast, &wt),
            PathBuf::from(format!("{base}.json"))
        );
        let other = WorktreeKey::of_realpath(Path::new("/home/u/Repos/myapp-fix-9"));
        assert_ne!(
            verify_checkout(root, &repo, Tier::Fast, &wt),
            verify_checkout(root, &repo, Tier::Fast, &other)
        );
        assert_ne!(
            verify_checkout(root, &repo, Tier::Fast, &wt),
            verify_checkout(root, &repo, Tier::Full, &wt)
        );
    }

    #[test]
    fn expand_tilde_only_expands_a_leading_tilde() {
        let d = Dirs::from_env(&env(&[("HOME", "/h")])).unwrap();
        assert_eq!(d.expand_tilde("~/Repos"), PathBuf::from("/h/Repos"));
        assert_eq!(d.expand_tilde("~"), PathBuf::from("/h"));
        assert_eq!(d.expand_tilde("/abs/~/x"), PathBuf::from("/abs/~/x"));
        assert_eq!(d.expand_tilde("~other/x"), PathBuf::from("~other/x"));
    }
}
