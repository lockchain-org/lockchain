//! Provider contract for LUKS-backed volumes.
//!
//! LUKS integration must work for both root and non-root devices. Root unlocks
//! typically rely on initrd tooling (`crypttab`, `cryptsetup`, dracut hooks),
//! while non-root devices can be handled post-boot via systemd units.

use std::error::Error;

/// Normalised state for a LUKS mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuksState {
    Active,
    Inactive,
    Unknown(String),
}

/// Descriptor for a managed LUKS mapping (typically sourced from crypttab).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuksMappingDescriptor {
    /// Logical mapping name (e.g. `cryptroot`, `vault`).
    pub name: String,
    /// Source device reference (e.g. `/dev/nvme0n1p3` or `UUID=...`).
    pub source: String,
    /// Current mapping state, as observed by the provider.
    pub state: LuksState,
}

/// Abstraction over LUKS key-management commands.
pub trait LuksProvider {
    type Error: Error + Send + Sync + 'static;

    /// Return the mappings this provider is able to manage.
    fn list_mappings(&self) -> Result<Vec<LuksMappingDescriptor>, Self::Error>;

    /// Attempt to unlock an encrypted mapping by name using the provided raw key bytes.
    fn unlock_mapping(&self, name: &str, key: &[u8]) -> Result<(), Self::Error>;

    /// Return the current mapping state for the named entry.
    fn mapping_state(&self, name: &str) -> Result<LuksState, Self::Error>;
}
