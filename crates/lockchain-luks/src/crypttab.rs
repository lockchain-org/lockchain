//! Minimal `crypttab` modelling helpers.
//!
//! The concrete parsing logic and validation rules will land in ADR-003
//! follow-ups. For now we keep the types close to the provider surface so
//! consumers can evolve without a giant refactor.

use lockchain_core::error::{LockchainError, LockchainResult};

/// One line of `/etc/crypttab`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct CrypttabEntry {
    pub name: String,
    pub source: String,
    pub key: Option<String>,
    pub options: Vec<String>,
}

/// Parse a `crypttab` document.
#[allow(dead_code)]
pub fn parse_crypttab(_contents: &str) -> LockchainResult<Vec<CrypttabEntry>> {
    Err(LockchainError::Provider("not implemented".into()))
}
