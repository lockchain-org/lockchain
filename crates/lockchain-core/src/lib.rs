//! Core building blocks shared by every Lockchain binary. Configuration,
//! workflows, and services all live here so downstream crates can focus on user
//! experience instead of reimplementing plumbing.

pub mod config;
pub mod error;
pub mod keyfile;
pub mod logging;
pub mod perf;
pub mod provider;
pub mod service;
pub mod workflow;

pub use config::{ConfigFormat, CryptoCfg, Fallback, LockchainConfig, Policy, Usb};
pub use error::{LockchainError, LockchainResult};
pub use provider::{DatasetKeyDescriptor, KeyState, KeyStatusSnapshot, ZfsProvider};
pub use service::{LockchainService, UnlockOptions, UnlockReport};
