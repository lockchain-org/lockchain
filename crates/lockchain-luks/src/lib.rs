#![forbid(unsafe_code)]

//! System provider for LUKS-backed volumes.
//!
//! This crate will own the host integration for:
//! - `cryptsetup` (open/close/status)
//! - `crypttab` modelling and validation
//! - initrd hooks (dracut + initramfs-tools) to wire root unlock

use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};

/// Placeholder system provider; implementation is added in ADR-003 follow-ups.
#[derive(Debug, Clone, Default)]
pub struct SystemLuksProvider;

impl LuksProvider for SystemLuksProvider {
    type Error = LockchainError;

    fn list_mappings(&self) -> LockchainResult<Vec<LuksMappingDescriptor>> {
        Err(LockchainError::Provider(
            "LUKS provider not implemented yet".into(),
        ))
    }

    fn unlock_mapping(&self, _name: &str, _key: &[u8]) -> LockchainResult<()> {
        Err(LockchainError::Provider(
            "LUKS provider not implemented yet".into(),
        ))
    }

    fn mapping_state(&self, _name: &str) -> LockchainResult<LuksState> {
        Err(LockchainError::Provider(
            "LUKS provider not implemented yet".into(),
        ))
    }
}
