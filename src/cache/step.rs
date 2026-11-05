//! Step-level reuse keys (L16).
//!
//! A step key is blake3 of the record and checks schemas, the tier (the
//! nextest profile and flaky policy differ per tier), the step definition
//! (canonical JSON of the policy's `[[step]]`), the fingerprint, and the
//! sorted `(path, oid, mode)` of the tree entries that match the
//! step's `inputs` minus `exclude_inputs`. A job may reuse a stored `pass` of
//! a step whose key matches. The caller also decides where reuse applies
//! (`fast` jobs and pushes of non-full refs; never `full` jobs for full refs
//! or CI) and that a reused `fast` result covers the selection needed now
//! ([`super::record::Selection::covers`]).

use std::io;
use std::os::unix::ffi::OsStrExt;

use serde::{Deserialize, Serialize};

use super::{CHECKS_SCHEMA, Fingerprint, RECORD_SCHEMA};
use crate::config::Tier;
use crate::config::repo::Step;
use crate::dirs::Dirs;
use crate::fsx;
use crate::gitx::TreeEntry;
use crate::ids::{JobId, StepKey};
use crate::steps::Scope;

/// The entries of `tree` that are inputs of `step`, sorted by path bytes.
pub fn step_inputs<'a>(step: &Step, tree: &'a [TreeEntry]) -> Result<Vec<&'a TreeEntry>, String> {
    let m = step.input_matcher()?;
    let mut inputs: Vec<&TreeEntry> = tree.iter().filter(|e| m.matches(&e.path)).collect();
    inputs.sort_by(|a, b| {
        a.path
            .as_os_str()
            .as_bytes()
            .cmp(b.path.as_os_str().as_bytes())
    });
    Ok(inputs)
}

/// The reuse key of `step` at `tier` on `tree` under `fingerprint` (L16).
pub fn step_key(
    step: &Step,
    tier: Tier,
    fingerprint: &Fingerprint,
    tree: &[TreeEntry],
) -> Result<StepKey, String> {
    let mut h = blake3::Hasher::new();
    // Length-prefixed fields: no two inputs hash the same bytes.
    let mut put = |bytes: &[u8]| {
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(bytes);
    };
    put(b"tollgate step key");
    put(&RECORD_SCHEMA.to_le_bytes());
    put(&CHECKS_SCHEMA.to_le_bytes());
    put(tier.as_str().as_bytes());
    put(&serde_json::to_vec(step).map_err(|e| e.to_string())?);
    put(&serde_json::to_vec(fingerprint).map_err(|e| e.to_string())?);
    for e in step_inputs(step, tree)? {
        put(e.path.as_os_str().as_bytes());
        put(e.oid.as_str().as_bytes());
        put(e.mode.as_bytes());
    }
    Ok(StepKey::from_hash(&h.finalize()))
}

/// A stored step pass (L16): `steps/<key[..2]>/<key>.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStep {
    /// The step key.
    pub key: StepKey,
    /// Step name.
    pub step: String,
    /// The job that ran it.
    pub job: JobId,
    /// What it checked.
    pub scope: Scope,
    /// When it finished.
    pub finished: jiff::Timestamp,
}

/// Reads the stored pass of `key`. Like records (R81), a pass whose job
/// report is gone does not count.
#[must_use]
pub fn read_stored(dirs: &Dirs, key: &StepKey) -> Option<StoredStep> {
    let bytes = fsx::read_optional(&dirs.step_result_file(key)).ok()??;
    let s: StoredStep = serde_json::from_slice(&bytes).ok()?;
    (s.key == *key && dirs.job_report(&s.job).is_file()).then_some(s)
}

/// Stores a step pass. A stored pass whose scope already covers this one
/// is kept.
pub fn write_stored(dirs: &Dirs, s: &StoredStep) -> io::Result<()> {
    if read_stored(dirs, &s.key).is_some_and(|old| old.scope.covers(&s.scope)) {
        return Ok(());
    }
    let json = serde_json::to_vec_pretty(s).map_err(io::Error::other)?;
    fsx::write_atomic(&dirs.step_result_file(&s.key), &json)
}
