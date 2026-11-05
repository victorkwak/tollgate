//! Process exit codes.
//!
//! R23: the guard exits only 0 or 2, and a panic exits 2. tollgate never exits
//! 101 (the Rust panic code), because it is not documented to block a
//! PreToolUse call.

/// Success, allow, pass.
pub const OK: u8 = 0;
/// Check failed, hook denies, command failed.
pub const FAIL: u8 = 1;
/// Guard block, usage error, panic (R23).
pub const BLOCK: u8 = 2;
/// `tollgate wait`: the job is still running (R99).
pub const RUNNING: u8 = 3;
/// Exit code after a caught panic (R23).
pub const PANIC: u8 = BLOCK;
