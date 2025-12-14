//! Glue layer that exposes the system-backed ZFS provider to the rest of the
//! Lockchain stack. The heavy lifting lives in `system`, while `command` and
//! `parse` cover shell integration details.

mod command;
mod parse;
mod system;

pub use system::{SystemZfsProvider, DEFAULT_ZFS_PATHS, DEFAULT_ZPOOL_PATHS};
