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

pub mod config;
pub mod dirs;
pub mod env;
pub mod exit;
pub mod fsx;
pub mod gitx;
pub mod guard;
pub mod hook;
pub mod ids;
pub mod install;
pub mod policy;
pub mod procs;
pub mod report;
pub mod runner;
pub mod select;
pub mod steps;

/// The version recorded in records and fingerprints (R74, R76).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
