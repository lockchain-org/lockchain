//! ZFS provider integration.
//!
//! `system` implements `ZfsProvider` using the host `zfs`/`zpool` CLIs. `command` and
//! `parse` isolate shell execution and output parsing so the provider stays testable.

mod command;
mod parse;
mod system;

pub use system::{SystemZfsProvider, DEFAULT_ZFS_PATHS, DEFAULT_ZPOOL_PATHS};
