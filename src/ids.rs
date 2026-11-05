//! Validated identifiers that become file names under the state dir.
//!
//! Each type checks its text on construction, so a value from the CLI or a
//! JSON file can never name a path outside its directory (`..`, `/`).

use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// Error for an identifier with the wrong form.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} {value:?}: {reason}")]
pub struct IdError {
    kind: &'static str,
    value: String,
    reason: &'static str,
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The cache key of a record: 64 lowercase hex characters of a blake3 hash (R74).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RecordKey(String);

impl RecordKey {
    /// Parses a key.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        if value.len() != 64 || !is_lower_hex(value) {
            return Err(IdError {
                kind: "record key",
                value: value.to_owned(),
                reason: "expected 64 lowercase hex characters",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The key for a blake3 hash.
    #[must_use]
    pub fn from_hash(hash: &blake3::Hash) -> Self {
        Self(hash.to_hex().to_string())
    }

    /// The key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first two characters: the shard directory of R76.
    #[must_use]
    pub fn shard(&self) -> &str {
        &self.0[..2]
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RecordKey {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<RecordKey> for String {
    fn from(value: RecordKey) -> Self {
        value.0
    }
}

/// A job id: `YYYYMMDD-HHMMSS-xxxxxxxx` (UTC start time, 8 hex characters).
///
/// Sortable by creation time and short enough to type in `tollgate wait <job>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct JobId(String);

static JOB_SEQ: AtomicU64 = AtomicU64::new(0);

impl JobId {
    /// Makes a new id for a job created at `now`.
    #[must_use]
    pub fn generate(now: jiff::Timestamp) -> Self {
        let dt = now.to_zoned(jiff::tz::TimeZone::UTC).datetime();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&std::process::id().to_le_bytes());
        hasher.update(&now.as_nanosecond().to_le_bytes());
        hasher.update(&JOB_SEQ.fetch_add(1, Ordering::Relaxed).to_le_bytes());
        let hex = hasher.finalize().to_hex();
        Self(format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}-{}",
            dt.year(),
            dt.month(),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
            &hex[..8]
        ))
    }

    /// Parses an id.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        let b = value.as_bytes();
        let ok = b.len() == 24
            && b[..8].iter().all(u8::is_ascii_digit)
            && b[8] == b'-'
            && b[9..15].iter().all(u8::is_ascii_digit)
            && b[15] == b'-'
            && is_lower_hex(&value[16..]);
        if !ok {
            return Err(IdError {
                kind: "job id",
                value: value.to_owned(),
                reason: "expected YYYYMMDD-HHMMSS-xxxxxxxx",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The id text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JobId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for JobId {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<JobId> for String {
    fn from(value: JobId) -> Self {
        value.0
    }
}

/// Identity of a repository clone: `blake3(realpath(common dir))[..16]` (R29, R41).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RepoKey(String);

impl RepoKey {
    /// The key of a common dir. `realpath` must already be canonical.
    #[must_use]
    pub fn of_realpath(realpath: &Path) -> Self {
        let hex = blake3::hash(realpath.as_os_str().as_bytes()).to_hex();
        Self(hex[..16].to_owned())
    }

    /// Parses a key.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        if value.len() != 16 || !is_lower_hex(value) {
            return Err(IdError {
                kind: "repo key",
                value: value.to_owned(),
                reason: "expected 16 lowercase hex characters",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for RepoKey {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<RepoKey> for String {
    fn from(value: RepoKey) -> Self {
        value.0
    }
}

/// A host resource name (`cpu`, `pg`, ...): the lock dir `locks/<name>` (R85).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ResourceName(String);

impl ResourceName {
    /// Parses a name: an ASCII letter or digit, then letters, digits, `_` or
    /// `-`; at most 64 characters.
    pub fn parse(value: &str) -> Result<Self, IdError> {
        let b = value.as_bytes();
        let ok = !b.is_empty()
            && b.len() <= 64
            && b[0].is_ascii_alphanumeric()
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'_' || *c == b'-');
        if !ok {
            return Err(IdError {
                kind: "resource name",
                value: value.to_owned(),
                reason: "use letters, digits, '_' or '-' (max 64), starting with a letter or digit",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// The name text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for ResourceName {
    type Error = IdError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl From<ResourceName> for String {
    fn from(value: ResourceName) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_key_rejects_paths_and_uppercase() {
        let good = "a".repeat(64);
        assert!(RecordKey::parse(&good).is_ok());
        assert_eq!(RecordKey::parse(&good).unwrap().shard(), "aa");
        assert!(RecordKey::parse(&"A".repeat(64)).is_err());
        assert!(RecordKey::parse("../../etc/passwd").is_err());
        assert!(RecordKey::parse(&"a".repeat(63)).is_err());
    }

    #[test]
    fn job_ids_are_unique_and_parse_back() {
        let now = jiff::Timestamp::from_second(1_793_862_075).unwrap();
        let a = JobId::generate(now);
        let b = JobId::generate(now);
        assert_ne!(a, b);
        assert!(a.as_str().starts_with("20261105-"), "{a}");
        assert_eq!(JobId::parse(a.as_str()).unwrap(), a);
        assert!(JobId::parse("20261105-012345-../../x").is_err());
        assert!(JobId::parse("").is_err());
    }

    #[test]
    fn job_id_serde_validates() {
        let err = serde_json::from_str::<JobId>("\"../x\"").unwrap_err();
        assert!(err.to_string().contains("job id"), "{err}");
    }

    #[test]
    fn repo_key_is_16_hex_of_the_path() {
        let k = RepoKey::of_path_for_test("/home/u/Repos/x/.git");
        assert_eq!(k.as_str().len(), 16);
        assert_eq!(k, RepoKey::of_path_for_test("/home/u/Repos/x/.git"));
        assert_ne!(k, RepoKey::of_path_for_test("/home/u/Repos/y/.git"));
    }

    impl RepoKey {
        fn of_path_for_test(p: &str) -> Self {
            Self::of_realpath(Path::new(p))
        }
    }

    #[test]
    fn resource_names_are_safe_dir_names() {
        for good in ["cpu", "pg", "minio", "gpu_0", "a-b"] {
            assert!(ResourceName::parse(good).is_ok(), "{good}");
        }
        for bad in ["", "..", "a/b", "-x", "_x", "x y", &"a".repeat(65)] {
            assert!(ResourceName::parse(bad).is_err(), "{bad}");
        }
    }
}
