//! Provider contracts used by `lockchain-core` workflows.
//!
//! Concrete implementations live in provider crates such as `lockchain-zfs` and
//! `lockchain-luks`. The shared traits/types are sourced from `lockchain-provider`
//! so the core crate stays focused on workflows and policy handling.

pub use lockchain_provider::zfs::{DatasetKeyDescriptor, KeyState, KeyStatusSnapshot, ZfsProvider};
