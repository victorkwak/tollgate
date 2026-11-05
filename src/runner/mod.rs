//! Job runner: detach, built environment, process groups, verify checkout,
//! setup, steps, records (R33-R35, R38, R40-R47, R52, L15, L16).

pub mod checkout;
pub mod env;
pub mod exec;
pub mod job;
pub mod setup;
pub mod spawn;
