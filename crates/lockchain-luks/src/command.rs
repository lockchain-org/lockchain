//! Execution wrapper for invoking `cryptsetup`.
//!
//! The goal is to keep shell integration isolated so provider logic stays
//! testable (fake binaries, deterministic stdout parsing, etc.).

use lockchain_core::error::{LockchainError, LockchainResult};
use lockchain_provider::luks::LuksState;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub(crate) struct CryptsetupCommand {
    #[allow(dead_code)]
    binary: PathBuf,
    #[allow(dead_code)]
    timeout: Duration,
}

impl CryptsetupCommand {
    pub(crate) fn new(binary: PathBuf, timeout: Duration) -> Self {
        Self { binary, timeout }
    }

    pub(crate) fn mapping_state(&self, _name: &str) -> LockchainResult<LuksState> {
        Err(LockchainError::Provider("not implemented".into()))
    }

    pub(crate) fn unlock_mapping(&self, _name: &str, _key: &[u8]) -> LockchainResult<()> {
        Err(LockchainError::Provider("not implemented".into()))
    }
}
