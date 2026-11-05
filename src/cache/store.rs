//! The record store: `results/<key[..2]>/<key>.json` (R76-R83).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::record::{Needed, Record, Selection, Verdict, VerdictClass};
use super::{Fingerprint, RECORD_SCHEMA, record_key};
use crate::config::Tier;
use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::Oid;
use crate::ids::RecordKey;

/// Error from the store.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// File system error.
    #[error("{path}: {source}")]
    Io {
        /// Path.
        path: PathBuf,
        /// Cause.
        #[source]
        source: io::Error,
    },
    /// A record file does not parse.
    #[error("{path}: corrupt record: {message}")]
    Corrupt {
        /// Path.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
    /// The record breaks a store rule and is not written.
    #[error("record not written: {0}")]
    Invalid(String),
}

/// What [`RecordStore::write`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// The record is stored.
    Written,
    /// A `fast` pass that already covers this selection is kept (R79).
    KeptBroader,
}

/// A lookup for a hook or `tollgate check` (R15).
#[derive(Debug, Clone, Copy)]
pub struct LookupRequest<'a> {
    /// The tree.
    pub tree: &'a Oid,
    /// The required tier.
    pub tier: Tier,
    /// The current fingerprint.
    pub fingerprint: &'a Fingerprint,
    /// The selection the current base needs; `Exact(All)` for `full`.
    pub needed: &'a Needed,
    /// Now, for TTLs.
    pub now: jiff::Timestamp,
}

/// What a lookup found (R15, R34, R78, R79).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// Allow.
    Pass(Record),
    /// Deny with the stored report; no job until `check --rerun`.
    Fail(Record),
    /// `timeout`/`error` inside its TTL: deny with the stored report and
    /// start no job.
    Environmental(Record),
    /// No usable record: start or attach a job.
    Miss,
}

/// The record store under the state dir.
#[derive(Debug, Clone)]
pub struct RecordStore {
    dirs: Dirs,
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> StoreError + '_ {
    move |source| StoreError::Io {
        path: path.to_owned(),
        source,
    }
}

impl RecordStore {
    /// The store of `dirs`.
    #[must_use]
    pub fn new(dirs: &Dirs) -> Self {
        Self { dirs: dirs.clone() }
    }

    /// The dirs of the store.
    #[must_use]
    pub fn dirs(&self) -> &Dirs {
        &self.dirs
    }

    /// Reads the record of `key`.
    pub fn read(&self, key: &RecordKey) -> Result<Option<Record>, StoreError> {
        let path = self.dirs.record_file(key);
        let Some(bytes) = fsx::read_optional(&path).map_err(io_err(&path))? else {
            return Ok(None);
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| StoreError::Corrupt {
                path,
                message: e.to_string(),
            })
    }

    /// R81: a record whose job `report.json` is gone is no record. A corrupt
    /// file is no record either: the job runs again.
    fn read_usable(&self, key: &RecordKey) -> Result<Option<Record>, StoreError> {
        match self.read(key) {
            Ok(Some(r)) if self.dirs.job_report(&r.job_id).is_file() => Ok(Some(r)),
            Ok(_) | Err(StoreError::Corrupt { .. }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn check(&self, r: &Record) -> Result<(), String> {
        if r.schema != RECORD_SCHEMA {
            return Err(format!("schema {} (expected {RECORD_SCHEMA})", r.schema));
        }
        if r.key != record_key(&r.tree, r.tier, &r.fingerprint) {
            return Err("key does not match tree, tier and fingerprint".into());
        }
        if r.verdict_class != r.verdict.class() {
            return Err("verdict class does not match the verdict".into());
        }
        match (r.verdict, r.cause) {
            (Verdict::Error, None) => return Err("an error record needs a cause".into()),
            (Verdict::Error, Some(c)) if !c.writes_record() => {
                return Err(format!("cause {c:?} writes no record (R34)"));
            }
            (Verdict::Error, Some(_)) | (_, None) => {}
            (_, Some(_)) => return Err("only error records have a cause".into()),
        }
        if r.tier == Tier::Full && r.selection != Selection::All {
            return Err("a full record checks everything (R54)".into());
        }
        if !self.dirs.job_report(&r.job_id).is_file() {
            return Err(format!(
                "job {} has no report.json (write it first, R81)",
                r.job_id
            ));
        }
        Ok(())
    }

    /// Writes `r` by atomic rename (R76). Refuses records that break R34,
    /// R54 or R81. A `fast` pass never replaces a `fast` pass that already
    /// covers its selection.
    pub fn write(&self, r: &Record) -> Result<WriteOutcome, StoreError> {
        self.check(r).map_err(StoreError::Invalid)?;
        if r.tier == Tier::Fast
            && r.verdict == Verdict::Pass
            && let Some(old) = self.read_usable(&r.key)?
            && old.verdict == Verdict::Pass
            && old.selection.covers(&r.selection)
        {
            return Ok(WriteOutcome::KeptBroader);
        }
        let path = self.dirs.record_file(&r.key);
        let json = serde_json::to_vec_pretty(r)
            .map_err(|e| StoreError::Invalid(format!("serialize: {e}")))?;
        fsx::write_atomic(&path, &json).map_err(io_err(&path))?;
        Ok(WriteOutcome::Written)
    }

    /// Removes the record of `key` (`check --rerun`, R34).
    pub fn remove(&self, key: &RecordKey) -> Result<bool, StoreError> {
        let path = self.dirs.record_file(key);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_err(&path)(e)),
        }
    }

    /// The lookup of R15, R34, R53, R78, R79, R81.
    ///
    /// - A `full` pass satisfies both tiers (R53).
    /// - `full`: a `full` fail denies; a `full` timeout/error denies inside
    ///   its TTL.
    /// - `fast`: a `fast` pass whose selection covers the needed one; a
    ///   `fast` fail or live timeout/error whose selection the needed one
    ///   covers (the same checks would run again).
    pub fn lookup(&self, req: &LookupRequest<'_>) -> Result<Lookup, StoreError> {
        let full_key = record_key(req.tree, Tier::Full, req.fingerprint);
        if let Some(r) = self.read_usable(&full_key)? {
            match r.verdict {
                Verdict::Pass => return Ok(Lookup::Pass(r)),
                Verdict::Fail if req.tier == Tier::Full => return Ok(Lookup::Fail(r)),
                Verdict::Timeout | Verdict::Error
                    if req.tier == Tier::Full && !r.expired(req.now) =>
                {
                    return Ok(Lookup::Environmental(r));
                }
                _ => {}
            }
        }
        if req.tier == Tier::Full {
            return Ok(Lookup::Miss);
        }
        let fast_key = record_key(req.tree, Tier::Fast, req.fingerprint);
        if let Some(r) = self.read_usable(&fast_key)? {
            match r.verdict {
                Verdict::Pass if req.needed.covered_by(&r.selection) => {
                    return Ok(Lookup::Pass(r));
                }
                Verdict::Fail if req.needed.contains(&r.selection) => return Ok(Lookup::Fail(r)),
                Verdict::Timeout | Verdict::Error
                    if r.verdict_class == VerdictClass::Environmental
                        && !r.expired(req.now)
                        && req.needed.contains(&r.selection) =>
                {
                    return Ok(Lookup::Environmental(r));
                }
                _ => {}
            }
        }
        Ok(Lookup::Miss)
    }

    /// Every readable record, for `audit` and `gc` (R48, R83).
    pub fn list(&self) -> Result<Vec<Record>, StoreError> {
        let root = self.dirs.results_dir();
        let mut out = Vec::new();
        let shards = match fs::read_dir(&root) {
            Ok(rd) => rd,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(io_err(&root)(e)),
        };
        for shard in shards {
            let shard = shard.map_err(io_err(&root))?.path();
            let Ok(files) = fs::read_dir(&shard) else {
                continue;
            };
            for f in files.flatten() {
                let name = f.file_name();
                let Some(key) = name
                    .to_str()
                    .and_then(|n| n.strip_suffix(".json"))
                    .and_then(|k| RecordKey::parse(k).ok())
                else {
                    continue;
                };
                if let Ok(Some(r)) = self.read(&key) {
                    out.push(r);
                }
            }
        }
        out.sort_by_key(|r| r.finished);
        Ok(out)
    }
}
