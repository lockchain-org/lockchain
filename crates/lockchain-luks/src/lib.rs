#![forbid(unsafe_code)]

//! System provider for LUKS-backed volumes.
//!
//! This crate will own the host integration for:
//! - `cryptsetup` (open/close/status)
//! - `crypttab` modelling and validation
//! - initrd hooks (dracut + initramfs-tools) to wire root unlock

mod command;
mod crypttab;
mod system;

pub use system::SystemLuksProvider;
