//! Workflow orchestration for provisioning, diagnostics, repair, and drills.

mod bootstrap;
mod diagnostics;
mod privilege;
mod provisioning;
mod repair;
mod self_test;
mod uninstall;

use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use crate::provider::ZfsProvider;
use crate::service::{LockchainService, UnlockOptions};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

pub use bootstrap::{
    bootstrap_plan, discover_topology, BootstrapCommand, BootstrapOptions, BootstrapPlan,
    BootstrapStep, BootstrapTopology, DatasetInfo, ZfsPoolInfo,
};
pub use diagnostics::{doctor, tune};
pub use privilege::ensure_privilege_support;
pub use provisioning::{
    discover_usb_candidates, forge_key, render_usb_selection_prompt, update_fallback_passphrase,
    usb_candidate_from_selector, ForgeMode, ProvisionOptions, UsbCandidate,
};
pub use repair::repair_environment;
pub use self_test::self_test;
pub use uninstall::uninstall;

/// Severity levels used when reporting workflow events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowLevel {
    Info,
    Success,
    Warn,
    Error,
    Security,
}

/// Single line of output produced by a workflow step.
#[derive(Debug, Clone)]
pub struct WorkflowEvent {
    pub level: WorkflowLevel,
    pub message: String,
}

/// Aggregated report returned by any workflow entry point.
#[derive(Debug, Clone)]
pub struct WorkflowReport {
    pub title: String,
    pub events: Vec<WorkflowEvent>,
    pub recovery_key: Option<String>,
}

/// Source material for recovery workflows.
pub enum RecoveryInput<'a> {
    /// Raw 32-byte key expressed as hexadecimal.
    Hex(&'a str),
    /// Passphrase that should be expanded through the configured fallback scheme.
    Passphrase(&'a [u8]),
}

/// Convenience constructor that wraps the repeated boilerplate.
pub(crate) fn event(level: WorkflowLevel, message: impl Into<String>) -> WorkflowEvent {
    WorkflowEvent {
        level,
        message: message.into(),
    }
}

/// Exercise the unlock path end-to-end and capture everything we learned.
pub fn drill_key<P>(
    config: &LockchainConfig,
    provider: P,
    dataset: &str,
    strict_usb: bool,
) -> LockchainResult<WorkflowReport>
where
    P: ZfsProvider<Error = LockchainError> + Clone,
{
    let mut events = Vec::new();
    let service = LockchainService::new(Arc::new(config.clone()), provider.clone());
    let options = UnlockOptions {
        strict_usb,
        ..UnlockOptions::default()
    };
    let report = service.unlock_with_retry(dataset, options)?;

    if report.already_unlocked {
        events.push(event(
            WorkflowLevel::Info,
            format!(
                "Encryption root {} already unlocked",
                report.encryption_root
            ),
        ));
    } else {
        events.push(event(
            WorkflowLevel::Success,
            format!(
                "Unlocked {} ({} datasets)",
                report.encryption_root,
                report.unlocked.len()
            ),
        ));
    }

    let locked_post = provider.locked_descendants(&report.encryption_root)?;
    if locked_post.iter().any(|ds| ds == &report.encryption_root) {
        events.push(event(
            WorkflowLevel::Warn,
            "Root still reports locked descendants after drill — investigate key content.",
        ));
    } else {
        events.push(event(
            WorkflowLevel::Info,
            "All descendants report unlocked after drill.",
        ));
    }

    Ok(WorkflowReport {
        title: format!("Drilled unlock sequence for {dataset}"),
        events,
        recovery_key: None,
    })
}

/// Recover fallback key material and write it to disk with the right permissions.
pub fn recover_key<P>(
    config: &LockchainConfig,
    provider: P,
    dataset: &str,
    recovery: RecoveryInput<'_>,
    output_path: &Path,
) -> LockchainResult<WorkflowReport>
where
    P: ZfsProvider<Error = LockchainError> + Clone,
{
    let mut events = Vec::new();
    let (key, via_hex) = match recovery {
        RecoveryInput::Hex(secret) => {
            let cleaned: String = secret.chars().filter(|c| !c.is_whitespace()).collect();
            if cleaned.len() != 64 || !cleaned.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Err(LockchainError::InvalidConfig(
                    "Recovery key must be 64 hexadecimal characters.".into(),
                ));
            }
            let bytes = hex::decode(&cleaned).map_err(|err| {
                LockchainError::InvalidConfig(format!("Invalid recovery key: {err}"))
            })?;
            (bytes, true)
        }
        RecoveryInput::Passphrase(passphrase) => {
            let service = LockchainService::new(Arc::new(config.clone()), provider.clone());
            let bytes = service
                .derive_fallback_key(passphrase)
                .map_err(|err| LockchainError::InvalidConfig(err.to_string()))?;
            (bytes.to_vec(), false)
        }
    };
    crate::keyfile::write_raw_key_file(output_path, &key)?;
    let digest = hex::encode(Sha256::digest(&key[..]));
    events.push(event(
        WorkflowLevel::Security,
        if via_hex {
            format!(
                "Recreated key material for {dataset} using recorded recovery key. Written to {}",
                output_path.display()
            )
        } else {
            format!(
                "Derived fallback key for {dataset} using recovery passphrase and wrote to {}",
                output_path.display()
            )
        },
    ));
    events.push(event(
        WorkflowLevel::Info,
        format!("SHA-256 of derived key: {digest}"),
    ));
    fs::set_permissions(output_path, std::fs::Permissions::from_mode(0o400))?;
    Ok(WorkflowReport {
        title: format!("Recovered key material for {dataset}"),
        events,
        recovery_key: None,
    })
}
