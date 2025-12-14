#![forbid(unsafe_code)]

//! Provider contracts shared across LockChain.
//!
//! The rest of the workspace is free to define workflows and operator surfaces
//! without depending on concrete system integrations.

pub mod luks;
pub mod zfs;

/// Identifies which storage provider a workflow or UI context is operating on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    Zfs,
    Luks,
}
