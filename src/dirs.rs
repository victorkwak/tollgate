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
//! - `jobs/<job id>/` with `report.json`, `<step>.log`, `junit.xml`, `tmp/` (R82),
//!   `waiters/` (R89), `job.json`
//! - `jobs/by-key/<key>.lock` (R88), `jobs/queue/<origin>/` (R89)
//! - `locks/<resource>/slot-<i>`, `locks/<resource>/queue/` (R85, R86)
//! - `flaky.jsonl` (R93)
//! - `verify/` (default `verify.root`, R41)
//!
//! A verify root holds `<repo key>/<tier>/wt`, `wt2`, ... with the lock files
//! `wt.lock`, `wt2.lock`, ... and the slot queue `queue/` (R41, R87).

use std::path::{Path, PathBuf};

use crate::config::Tier;
use crate::env::EnvSnapshot;
use crate::ids::{JobId, RecordKey, RepoKey, ResourceName};

const APP: &str = "tollgate";

/// Error when the base dirs cannot be found.
#[derive(Debug, thiserror::Error)]
pub enum DirsError {
    /// `HOME` is unset, empty or relative.
    #[error("HOME is not set to an absolute path")]
    NoHome,
}

/// The resolved base dirs.
#[derive(Debug, Clone, PartialEq, Eq)]
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
}

/// `<verify root>/<repo key>/<tier>/`: checkouts, their locks and the slot queue.
#[must_use]
pub fn verify_tier_dir(verify_root: &Path, repo: &RepoKey, tier: Tier) -> PathBuf {
    verify_root.join(repo.as_str()).join(tier.as_str())
}

/// File name of verify checkout `slot` (0-based): `wt`, `wt2`, `wt3`, ... (R41).
#[must_use]
pub fn verify_checkout_name(slot: u32) -> String {
    if slot == 0 {
        "wt".to_owned()
    } else {
        format!("wt{}", slot + 1)
    }
}

/// The verify checkout of `slot` (R41).
#[must_use]
pub fn verify_checkout(verify_root: &Path, repo: &RepoKey, tier: Tier, slot: u32) -> PathBuf {
    verify_tier_dir(verify_root, repo, tier).join(verify_checkout_name(slot))
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
    fn verify_checkout_names_r41() {
        let repo = RepoKey::parse("0123456789abcdef").unwrap();
        let root = Path::new("/v");
        assert_eq!(
            verify_checkout(root, &repo, Tier::Fast, 0),
            PathBuf::from("/v/0123456789abcdef/fast/wt")
        );
        assert_eq!(
            verify_checkout(root, &repo, Tier::Full, 2),
            PathBuf::from("/v/0123456789abcdef/full/wt3")
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
