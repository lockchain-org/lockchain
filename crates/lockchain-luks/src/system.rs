//! System-backed `LuksProvider` implementation.
//!
//! This module will grow into the host integration layer for ADR-003 (wrapping
//! `cryptsetup`, modelling `crypttab`, and shipping initrd hooks).

use crate::command::CryptsetupCommand;
use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_core::LockchainConfig;
use lockchain_provider::luks::{LuksMappingDescriptor, LuksProvider, LuksState};
use std::path::Path;

/// Placeholder system provider; implementation is added in ADR-003 follow-ups.
#[derive(Debug, Clone, Default)]
pub struct SystemLuksProvider {
    #[allow(dead_code)]
    cryptsetup: Option<CryptsetupCommand>,
}

impl SystemLuksProvider {
    pub fn from_config(config: &LockchainConfig) -> LockchainResult<Self> {
        let timeout = config.zfs_timeout();
        let cryptsetup = match config.luks.cryptsetup_path.as_deref() {
            Some(path) => {
                let candidate = Path::new(path);
                if !candidate.exists() {
                    return Err(LockchainError::InvalidConfig(format!(
                        "cryptsetup binary not found at {}",
                        candidate.display()
                    )));
                }
                Some(CryptsetupCommand::new(candidate.to_path_buf(), timeout))
            }
            None => None,
        };
        Ok(Self { cryptsetup })
    }

    /// Provider-specific status entry point (scaffold).
    pub fn status(&self, name: &str) -> LockchainResult<LuksState> {
        self.mapping_state(name)
    }

    /// Provider-specific unlock entry point (scaffold).
    pub fn unlock(&self, name: &str, key: &[u8]) -> LockchainResult<()> {
        self.unlock_mapping(name, key)
    }

    /// Provider-specific init entry point (scaffold).
    pub fn init(&self) -> LockchainResult<()> {
        Err(LockchainError::Provider("not implemented".into()))
    }

    /// Provider-specific self-test entry point (scaffold).
    pub fn self_test(&self) -> LockchainResult<()> {
        Err(LockchainError::Provider("not implemented".into()))
    }

    /// Provider-specific validation entry point (scaffold).
    pub fn validate(&self) -> LockchainResult<()> {
        Err(LockchainError::Provider("not implemented".into()))
    }
}

impl LuksProvider for SystemLuksProvider {
    type Error = LockchainError;

    fn list_mappings(&self) -> LockchainResult<Vec<LuksMappingDescriptor>> {
        Err(LockchainError::Provider("not implemented".into()))
    }

    fn unlock_mapping(&self, name: &str, key: &[u8]) -> LockchainResult<()> {
        if let Some(cryptsetup) = &self.cryptsetup {
            return cryptsetup.unlock_mapping(name, key);
        }
        Err(LockchainError::Provider("not implemented".into()))
    }

    fn mapping_state(&self, name: &str) -> LockchainResult<LuksState> {
        if let Some(cryptsetup) = &self.cryptsetup {
            return cryptsetup.mapping_state(name);
        }
        Err(LockchainError::Provider("not implemented".into()))
    }
}
