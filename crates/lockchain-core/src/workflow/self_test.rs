//! End-to-end self-test that spins up a temporary ZFS pool to validate unlock flows.

use super::{event, WorkflowLevel, WorkflowReport};
use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use crate::keyfile::{read_key_file, write_raw_key_file};
use crate::provider::ZfsProvider;
use crate::service::{LockchainService, UnlockOptions};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::TempDir;

const DEFAULT_ZFS_PATHS: &[&str] = &[
    "/sbin/zfs",
    "/usr/sbin/zfs",
    "/usr/local/sbin/zfs",
    "/bin/zfs",
];

const DEFAULT_ZPOOL_PATHS: &[&str] = &[
    "/sbin/zpool",
    "/usr/sbin/zpool",
    "/usr/local/sbin/zpool",
    "/bin/zpool",
];

/// Spin up a throwaway ZFS pool, exercise the unlock workflow, and tear it down.
pub fn self_test<P: ZfsProvider<Error = LockchainError> + Clone>(
    config: &LockchainConfig,
    provider: P,
    dataset: &str,
    strict_usb: bool,
) -> LockchainResult<WorkflowReport> {
    let mut events = Vec::new();
    let key_path = config.key_hex_path();
    if !key_path.exists() {
        return Err(LockchainError::MissingKeySource(dataset.to_string()));
    }

    let (key_material, converted) = read_key_file(&key_path)?;
    if converted {
        write_raw_key_file(&key_path, &key_material[..])?;
        events.push(event(
            WorkflowLevel::Warn,
            format!(
                "Key material at {} was hex encoded; normalised to raw bytes (0o400) before testing.",
                key_path.display()
            ),
        ));
    }

    if key_material.len() != 32 {
        return Err(LockchainError::InvalidConfig(format!(
            "self-test requires 32-byte raw key material (found {} bytes)",
            key_material.len()
        )));
    }

    let key_digest = hex::encode(Sha256::digest(&key_material[..]));
    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Using key {} (SHA-256 {}) for self-test",
            key_path.display(),
            key_digest
        ),
    ));

    let zfs_path = resolve_binary(config.zfs_binary_path(), DEFAULT_ZFS_PATHS, "zfs")?;
    let zpool_path = resolve_binary(config.zpool_binary_path(), DEFAULT_ZPOOL_PATHS, "zpool")?;

    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Using binaries zfs={} zpool={}",
            zfs_path.display(),
            zpool_path.display()
        ),
    ));

    let mut ctx = SimulationContext::prepare(&zfs_path, &zpool_path)?;
    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Created simulated pool {} backed by {}",
            ctx.pool_name,
            ctx.image_path.display()
        ),
    ));

    create_encrypted_dataset(&zfs_path, &ctx.dataset_name, &key_path, &mut events)?;
    ctx.dataset_created = true;

    unload_key(&zfs_path, &ctx.dataset_name, &mut events)?;

    let sim_config = build_simulation_config(config, &ctx.dataset_name, &key_path, &key_material);
    let options = UnlockOptions {
        strict_usb,
        ..UnlockOptions::default()
    };
    let service = LockchainService::new(Arc::new(sim_config.clone()), provider.clone());
    let report = service.unlock_with_retry(&ctx.dataset_name, options)?;

    if report.already_unlocked {
        events.push(event(
            WorkflowLevel::Info,
            "Dataset already unlocked when self-test began; continuing verification.",
        ));
    } else {
        events.push(event(
            WorkflowLevel::Success,
            format!(
                "Self-test unlock succeeded for {} ({} datasets).",
                report.encryption_root,
                report.unlocked.len()
            ),
        ));
    }
    if !report.unlocked.is_empty() {
        events.push(event(
            WorkflowLevel::Info,
            format!(
                "Unlocked datasets during self-test: {}",
                report.unlocked.join(", ")
            ),
        ));
    }

    verify_keystatus(&zfs_path, &ctx.dataset_name, "available", &mut events)?;

    unload_key(&zfs_path, &ctx.dataset_name, &mut events)?;
    verify_keystatus(&zfs_path, &ctx.dataset_name, "unavailable", &mut events)?;

    destroy_dataset(&zfs_path, &ctx.dataset_name, &mut events)?;
    ctx.dataset_created = false;
    destroy_pool(&zpool_path, &ctx.pool_name, &mut events)?;
    ctx.pool_created = false;
    ctx.cleaned = true;

    events.push(event(
        WorkflowLevel::Success,
        "Self-test completed; ephemeral pool dismantled.",
    ));

    Ok(WorkflowReport {
        title: "Self-test vault simulation".into(),
        events,
        recovery_key: None,
    })
}

/// Locate the requested binary, preferring explicit config over defaults.
fn resolve_binary(
    configured: Option<PathBuf>,
    defaults: &[&str],
    label: &str,
) -> LockchainResult<PathBuf> {
    if let Some(path) = configured {
        if path.exists() {
            return Ok(path);
        }
        return Err(LockchainError::InvalidConfig(format!(
            "{label} binary configured at {} but missing",
            path.display()
        )));
    }

    for candidate in defaults {
        let path = Path::new(candidate);
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }

    Err(LockchainError::InvalidConfig(format!(
        "unable to locate {label} binary; tried {:?}",
        defaults
    )))
}

/// Create a child dataset with encryption enabled and key material bound to disk.
fn create_encrypted_dataset(
    zfs_path: &Path,
    dataset: &str,
    key_path: &Path,
    events: &mut Vec<super::WorkflowEvent>,
) -> LockchainResult<()> {
    let keylocation = format!("keylocation=file://{}", key_path.display());
    let args = vec![
        "create".to_string(),
        "-o".to_string(),
        "encryption=on".to_string(),
        "-o".to_string(),
        "keyformat=raw".to_string(),
        "-o".to_string(),
        keylocation,
        "-o".to_string(),
        "mountpoint=none".to_string(),
        dataset.to_string(),
    ];
    run_command(zfs_path, &args)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Created encrypted dataset {dataset} using key {key_path:?}"),
    ));
    Ok(())
}

/// Run `zfs unload-key` for the generated dataset.
fn unload_key(
    zfs_path: &Path,
    dataset: &str,
    events: &mut Vec<super::WorkflowEvent>,
) -> LockchainResult<()> {
    let args = vec!["unload-key".to_string(), dataset.to_string()];
    run_command(zfs_path, &args)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Unloaded key for {dataset}"),
    ));
    Ok(())
}

/// Recursively destroy the simulated dataset hierarchy.
fn destroy_dataset(
    zfs_path: &Path,
    dataset: &str,
    events: &mut Vec<super::WorkflowEvent>,
) -> LockchainResult<()> {
    let args = vec!["destroy".to_string(), "-r".to_string(), dataset.to_string()];
    run_command(zfs_path, &args)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Destroyed dataset {dataset}"),
    ));
    Ok(())
}

/// Tear down the temporary pool after the drill finishes.
fn destroy_pool(
    zpool_path: &Path,
    pool: &str,
    events: &mut Vec<super::WorkflowEvent>,
) -> LockchainResult<()> {
    let args = vec!["destroy".to_string(), pool.to_string()];
    run_command(zpool_path, &args)?;
    events.push(event(WorkflowLevel::Info, format!("Destroyed pool {pool}")));
    Ok(())
}

/// Confirm the dataset reports the expected `keystatus` value.
fn verify_keystatus(
    zfs_path: &Path,
    dataset: &str,
    expected: &str,
    events: &mut Vec<super::WorkflowEvent>,
) -> LockchainResult<()> {
    let output = Command::new(zfs_path)
        .args(["get", "-H", "-o", "value", "keystatus", dataset])
        .output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;
    if !output.status.success() {
        return Err(LockchainError::Provider(format!(
            "zfs get keystatus {} failed: {}",
            dataset,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let status = String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_string()
        .to_lowercase();
    if status == expected {
        events.push(event(
            WorkflowLevel::Info,
            format!("keystatus for {dataset} = {status}"),
        ));
        Ok(())
    } else {
        Err(LockchainError::Provider(format!(
            "expected keystatus {expected} for {dataset}, got {status}"
        )))
    }
}

/// Execute a ZFS/ZPOOL command and convert failures into provider errors.
fn run_command(binary: &Path, args: &[String]) -> LockchainResult<()> {
    let output = Command::new(binary)
        .args(args)
        .output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    if !output.status.success() {
        return Err(LockchainError::Provider(format!(
            "{} {} failed: {}",
            binary.display(),
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

/// Prepare a config clone wired to the simulated dataset and USB path.
fn build_simulation_config(
    base: &LockchainConfig,
    dataset: &str,
    key_path: &Path,
    key_material: &[u8],
) -> LockchainConfig {
    let mut cfg = base.clone();
    cfg.policy.targets = vec![dataset.to_string()];
    cfg.usb.key_hex_path = key_path.to_string_lossy().into_owned();
    if cfg.usb.expected_sha256.is_none() {
        cfg.usb.expected_sha256 = Some(hex::encode(Sha256::digest(key_material)));
    }
    cfg.fallback = base.fallback.clone();
    cfg.retry = base.retry.clone();
    cfg
}

/// Tracks the temporary resources created for the self-test run.
struct SimulationContext {
    _temp_dir: TempDir,
    image_path: PathBuf,
    pool_name: String,
    dataset_name: String,
    zfs_path: PathBuf,
    zpool_path: PathBuf,
    cleaned: bool,
    dataset_created: bool,
    pool_created: bool,
}

impl SimulationContext {
    /// Allocate backing storage, create a pool, and return the guard context.
    fn prepare(zfs_path: &Path, zpool_path: &Path) -> LockchainResult<Self> {
        let temp_dir = TempDir::new().map_err(|err| LockchainError::Provider(err.to_string()))?;
        let image_path = temp_dir.path().join("lockchain-selftest.img");
        let backing =
            File::create(&image_path).map_err(|err| LockchainError::Provider(err.to_string()))?;
        backing
            .set_len(256 * 1024 * 1024)
            .map_err(|err| LockchainError::Provider(err.to_string()))?;

        let pool_name = format!(
            "lcst_{}",
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(6)
                .map(char::from)
                .collect::<String>()
                .to_lowercase()
        );
        let dataset_name = format!("{}/vault", pool_name);

        let backing = image_path.to_string_lossy().into_owned();
        let args = vec![
            "create".to_string(),
            "-f".to_string(),
            pool_name.clone(),
            backing,
        ];
        run_command(zpool_path, &args)?;

        Ok(Self {
            _temp_dir: temp_dir,
            image_path,
            pool_name,
            dataset_name,
            zfs_path: zfs_path.to_path_buf(),
            zpool_path: zpool_path.to_path_buf(),
            cleaned: false,
            dataset_created: false,
            pool_created: true,
        })
    }
}

impl Drop for SimulationContext {
    fn drop(&mut self) {
        if self.dataset_created {
            let _ = Command::new(&self.zfs_path)
                .args(["destroy", "-r", &self.dataset_name])
                .status();
        }
        if self.pool_created && !self.cleaned {
            let _ = Command::new(&self.zpool_path)
                .args(["destroy", &self.pool_name])
                .status();
        }
    }
}
