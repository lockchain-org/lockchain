#![forbid(unsafe_code)]

//! Provider contracts shared across LockChain.
//!
//! The rest of the workspace is free to define workflows and operator surfaces
//! without depending on concrete system integrations.

pub mod luks;
pub mod zfs;

/// Identifies which storage provider a workflow or UI context is operating on.
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum ProviderKind {
    Zfs,
    Luks,
    /// Auto-detect which provider to use from configuration and host tooling.
    Auto,
}

impl Default for ProviderKind {
    fn default() -> Self {
        ProviderKind::Auto
    }
}
