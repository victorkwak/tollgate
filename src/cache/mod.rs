//! Result cache: key, fingerprint, tool version cache, records (R74-R83).
//!
//! A record is keyed by `blake3` of the canonical JSON
//! `{checks_schema, fingerprint, schema, tier, tree}` (R74). The tree covers
//! lockfiles, repo config and source; the fingerprint covers what lies
//! outside the tree (toolchain, host config, job environment, images,
//! tollgate itself).

pub mod fingerprint;
pub mod record;
pub mod store;
pub mod toolcache;

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::config::Tier;
use crate::gitx::Oid;
use crate::ids::RecordKey;

/// Version of the record file format and key layout.
pub const RECORD_SCHEMA: u32 = 1;

/// R74: bump on every change to step kinds, selection, parsing or verdict
/// logic, so records made by older logic stop matching.
pub const CHECKS_SCHEMA: u32 = 1;

/// The sorted map of outside inputs (R74).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Fingerprint(BTreeMap<String, String>);

impl Fingerprint {
    /// An empty fingerprint.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets one input.
    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.0.insert(key.into(), value.into());
    }

    /// One input.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// All inputs in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of inputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Fields in alphabetical order: serde_json writes struct fields in
/// declaration order and the fingerprint map sorted, so the JSON is
/// canonical.
#[derive(Serialize)]
struct KeyInput<'a> {
    checks_schema: u32,
    fingerprint: &'a Fingerprint,
    schema: u32,
    tier: Tier,
    tree: &'a Oid,
}

/// The record key of `tree` at `tier` under `fingerprint` (R74).
#[must_use]
pub fn record_key(tree: &Oid, tier: Tier, fingerprint: &Fingerprint) -> RecordKey {
    record_key_with(RECORD_SCHEMA, CHECKS_SCHEMA, tree, tier, fingerprint)
}

/// [`record_key`] with explicit schema numbers (tests show a bump changes it).
#[must_use]
pub fn record_key_with(
    schema: u32,
    checks_schema: u32,
    tree: &Oid,
    tier: Tier,
    fingerprint: &Fingerprint,
) -> RecordKey {
    let json = serde_json::to_vec(&KeyInput {
        checks_schema,
        fingerprint,
        schema,
        tier,
        tree,
    })
    .expect("key input serializes");
    RecordKey::from_hash(&blake3::hash(&json))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> Oid {
        Oid::parse(&"ab".repeat(20)).unwrap()
    }

    #[test]
    fn key_json_is_canonical() {
        let mut fp = Fingerprint::new();
        fp.insert("rustc", "1.96.1");
        fp.insert("git", "2.56.0");
        let json = serde_json::to_string(&KeyInput {
            checks_schema: 1,
            fingerprint: &fp,
            schema: 1,
            tier: Tier::Fast,
            tree: &tree(),
        })
        .unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"checks_schema\":1,\"fingerprint\":{{\"git\":\"2.56.0\",\"rustc\":\"1.96.1\"}},\"schema\":1,\"tier\":\"fast\",\"tree\":\"{}\"}}",
                tree()
            )
        );
    }

    #[test]
    fn every_input_changes_the_key_r74_t36() {
        let mut fp = Fingerprint::new();
        fp.insert("rustc", "rustc 1.96.1");
        let base = record_key(&tree(), Tier::Fast, &fp);
        assert_eq!(base, record_key(&tree(), Tier::Fast, &fp));
        assert_ne!(base, record_key(&tree(), Tier::Full, &fp));
        let other_tree = Oid::parse(&"cd".repeat(20)).unwrap();
        assert_ne!(base, record_key(&other_tree, Tier::Fast, &fp));
        let mut fp2 = fp.clone();
        fp2.insert("rustc", "rustc 1.97.0");
        assert_ne!(base, record_key(&tree(), Tier::Fast, &fp2));
        let mut fp3 = fp.clone();
        fp3.insert("job-env", "x");
        assert_ne!(base, record_key(&tree(), Tier::Fast, &fp3));
        assert_ne!(
            base,
            record_key_with(RECORD_SCHEMA, CHECKS_SCHEMA + 1, &tree(), Tier::Fast, &fp)
        );
        assert_ne!(
            base,
            record_key_with(RECORD_SCHEMA + 1, CHECKS_SCHEMA, &tree(), Tier::Fast, &fp)
        );
    }
}
