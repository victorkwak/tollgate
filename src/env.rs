//! A captured process environment.
//!
//! Code reads the environment through an [`EnvSnapshot`] that `main` captures
//! once, never through `std::env::var` at the point of use. Tests build
//! snapshots with temporary `HOME`/`XDG_*` values and never mutate the test
//! process environment (that is `unsafe` in edition 2024 and races between
//! test threads).

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

/// An immutable-by-default copy of environment variables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvSnapshot {
    vars: BTreeMap<OsString, OsString>,
}

impl EnvSnapshot {
    /// Copies the environment of the current process.
    #[must_use]
    pub fn capture() -> Self {
        Self {
            vars: std::env::vars_os().collect(),
        }
    }

    /// Builds a snapshot from explicit pairs.
    #[must_use]
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        Self {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
        }
    }

    /// The value of `key`, also when it is empty.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&OsStr> {
        self.vars.get(OsStr::new(key)).map(OsString::as_os_str)
    }

    /// The value of `key` when it is set and not empty.
    #[must_use]
    pub fn get_nonempty(&self, key: &str) -> Option<&OsStr> {
        self.get(key).filter(|v| !v.is_empty())
    }

    /// The value of `key` as UTF-8, when set, not empty and valid UTF-8.
    #[must_use]
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get_nonempty(key).and_then(OsStr::to_str)
    }

    /// Sets `key` to `value`.
    pub fn set(&mut self, key: impl Into<OsString>, value: impl Into<OsString>) {
        self.vars.insert(key.into(), value.into());
    }

    /// Removes `key` and returns its old value.
    pub fn remove(&mut self, key: &str) -> Option<OsString> {
        self.vars.remove(OsStr::new(key))
    }

    /// Returns the snapshot with `key` set to `value`.
    #[must_use]
    pub fn with(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.set(key, value);
        self
    }

    /// Returns the snapshot without `key`.
    #[must_use]
    pub fn without(mut self, key: &str) -> Self {
        self.remove(key);
        self
    }

    /// All variables in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.vars
            .iter()
            .map(|(k, v)| (k.as_os_str(), v.as_os_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_nonempty_ignores_empty_values() {
        let env = EnvSnapshot::from_pairs([("A", ""), ("B", "x")]);
        assert_eq!(env.get("A"), Some(OsStr::new("")));
        assert_eq!(env.get_nonempty("A"), None);
        assert_eq!(env.get_str("B"), Some("x"));
        assert_eq!(env.get("C"), None);
    }

    #[test]
    fn with_and_without_edit_a_copy() {
        let env = EnvSnapshot::default().with("A", "1").with("B", "2");
        let fewer = env.clone().without("A");
        assert_eq!(env.get_str("A"), Some("1"));
        assert_eq!(fewer.get("A"), None);
        assert_eq!(fewer.iter().count(), 1);
    }
}
