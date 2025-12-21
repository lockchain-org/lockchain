//! Shared error codes and result aliases for `lockchain-core`.

use std::path::PathBuf;
use thiserror::Error;

/// Result alias for core operations.
pub type LockchainResult<T> = Result<T, LockchainError>;

/// Canonical error list for LockChain operations.
#[derive(Error, Debug)]
pub enum LockchainError {
    #[error("[LC1000] io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("[LC1001] toml config parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("[LC1002] yaml config parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("[LC1003] toml config serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("[LC1100] configuration error: {0}")]
    InvalidConfig(String),

    #[error("[LC1101] provider selection error: {0}")]
    ProviderSelection(String),

    #[error("[LC1200] target `{0}` is not declared in policy")]
    DatasetNotConfigured(String),

    #[error("[LC1201] no key source configured for target `{0}`")]
    MissingKeySource(String),

    #[error("[LC1300] failed to decode hex key at {path}: {reason}")]
    InvalidHexKey { path: PathBuf, reason: String },

    #[error("[LC2000] provider error: {0}")]
    Provider(String),

    #[error("[LC2100] privilege escalation unavailable: {0}")]
    Privilege(String),

    #[error("[LC3000] unlock retries exhausted after {attempts} attempts: {last_error}")]
    RetryExhausted { attempts: u32, last_error: String },
}

impl LockchainError {
    /// Return the stable LCxxxx code associated with this error variant.
    pub fn code(&self) -> &'static str {
        match self {
            LockchainError::Io(_) => "LC1000",
            LockchainError::Toml(_) => "LC1001",
            LockchainError::Yaml(_) => "LC1002",
            LockchainError::TomlSer(_) => "LC1003",
            LockchainError::InvalidConfig(_) => "LC1100",
            LockchainError::ProviderSelection(_) => "LC1101",
            LockchainError::DatasetNotConfigured(_) => "LC1200",
            LockchainError::MissingKeySource(_) => "LC1201",
            LockchainError::InvalidHexKey { .. } => "LC1300",
            LockchainError::Provider(_) => "LC2000",
            LockchainError::Privilege(_) => "LC2100",
            LockchainError::RetryExhausted { .. } => "LC3000",
        }
    }
}
