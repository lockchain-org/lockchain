#![forbid(unsafe_code)]

//! System provider for LUKS-backed volumes.
//!
//! This crate will own the host integration for:
//! - `cryptsetup` (open/close/status)
//! - `crypttab` modelling and validation
//! - initrd hooks (dracut + initramfs-tools) to wire root unlock

use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_core::LockchainConfig;
use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};
use std::path::Path;

/// Placeholder system provider; implementation is added in ADR-003 follow-ups.
#[derive(Debug, Clone, Default)]
pub struct SystemLuksProvider;

impl SystemLuksProvider {
    pub fn from_config(config: &LockchainConfig) -> LockchainResult<Self> {
        if let Some(path) = config.luks.cryptsetup_path.as_deref() {
            let candidate = Path::new(path);
            if !candidate.exists() {
                return Err(LockchainError::InvalidConfig(format!(
                    "cryptsetup binary not found at {}",
                    candidate.display()
                )));
            }
        }
        Ok(Self)
    }
}

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
