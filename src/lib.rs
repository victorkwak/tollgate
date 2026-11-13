//! tollgate: gates the git ref updates that a Claude Code session makes.
//!
//! The design is `docs/spec.md` (v3). Requirement ids (`R<n>`, `L<n>`) in doc
//! comments and test names point into that file. The "Lead decisions (v3)"
//! section overrides the requirements below it; CUT items are not built.
//!
//! `src/main.rs` is a thin shell (argv\[0\] dispatch, CLI, exit codes) over this
//! library, so integration tests can drive every module.

#[cfg(not(unix))]
compile_error!("tollgate supports Linux and macOS only (L13)");

pub mod bench;
pub mod cache;
pub mod ci;
pub mod cli;
pub mod config;
pub mod dirs;
pub mod env;
pub mod exit;
pub mod fsx;
pub mod gc;
pub mod gitx;
pub mod guard;
pub mod hook;
pub mod ids;
pub mod install;
pub mod locks;
pub mod merge;
pub mod metrics;
pub mod plan;
pub mod policy;
pub mod procs;
pub mod remote_record;
pub mod remote_refs;
pub mod report;
pub mod runner;
pub mod sched;
pub mod select;
pub mod steps;

/// The package version, recorded in records (R76). Not in the fingerprint:
/// that holds [`cache::RECORD_EPOCH`] (R110).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The git commit this binary was built from: 12 hex digits, with `-dirty`
/// when the checkout had changes; `None` when the build did not know it
/// (`build.rs`). It names a build for people and for `doctor` (R97). It is
/// never part of a record or a fingerprint: a commit there would void every
/// stored result on each build.
pub const GIT_COMMIT: Option<&str> = option_env!("TOLLGATE_GIT_COMMIT");

/// What `tollgate --version` prints after the name: the version, and the
/// commit in parentheses when it is known.
pub const BUILD: &str = match option_env!("TOLLGATE_BUILD") {
    Some(build) => build,
    None => VERSION,
};
