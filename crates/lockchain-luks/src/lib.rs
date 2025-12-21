#![forbid(unsafe_code)]

//! System provider for LUKS-backed mappings.
//!
//! Integrates with the host via:
//! - `cryptsetup` (open/close/status)
//! - `/etc/crypttab` parsing
//! - initrd hooks (dracut + initramfs-tools) for root unlock (ADR-003)

mod command;
mod crypttab;
mod system;

pub use system::SystemLuksProvider;
