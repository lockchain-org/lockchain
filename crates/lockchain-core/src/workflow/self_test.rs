//! End-to-end self-tests that validate unlock workflows.
//!
//! ZFS runs against an ephemeral pool; LUKS runs against a loopback mapping with a staged
//! `crypttab` entry.

use super::{event, WorkflowLevel, WorkflowReport};
use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use crate::keyfile::{read_key_file, write_raw_key_file};
use crate::provider::{LuksKeyProvider, LuksProvider, ProviderKind, ZfsProvider};
use crate::service::{LockchainService, UnlockOptions};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tempfile::TempDir;
use zeroize::Zeroizing;

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

const DEFAULT_CRYPTSETUP_PATHS: &[&str] = &[
    "/usr/sbin/cryptsetup",
    "/usr/bin/cryptsetup",
    "/sbin/cryptsetup",
    "/bin/cryptsetup",
    "/usr/local/sbin/cryptsetup",
];

const DEFAULT_LOSETUP_PATHS: &[&str] = &[
    "/usr/sbin/losetup",
    "/usr/bin/losetup",
    "/sbin/losetup",
    "/bin/losetup",
    "/usr/local/sbin/losetup",
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

/// Spin up a throwaway loopback LUKS volume, exercise enrollment + unlock + checksum gating, and tear it down.
pub fn self_test_luks<P, F>(
    config: &LockchainConfig,
    provider_builder: F,
    target: &str,
    strict_usb: bool,
) -> LockchainResult<WorkflowReport>
where
    P: LuksProvider<Error = LockchainError> + Clone,
    F: FnOnce(&LockchainConfig) -> LockchainResult<P>,
{
    let mut events = Vec::new();
    let key_path = config.key_hex_path();
    if !key_path.exists() {
        return Err(LockchainError::MissingKeySource(target.to_string()));
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

    let cryptsetup_path = resolve_binary_path(
        config
            .luks
            .cryptsetup_path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        DEFAULT_CRYPTSETUP_PATHS,
        "cryptsetup",
    )?;
    let losetup_path = resolve_binary_path(None, DEFAULT_LOSETUP_PATHS, "losetup")?;

    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Using binaries cryptsetup={} losetup={}",
            cryptsetup_path.display(),
            losetup_path.display()
        ),
    ));

    let mut ctx = LuksSimulationContext::prepare(&cryptsetup_path, &losetup_path)?;
    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Created simulated LUKS volume {} backed by {} ({})",
            ctx.mapping_name,
            ctx.image_path.display(),
            ctx.loop_device
        ),
    ));

    luks_format(&cryptsetup_path, &ctx.loop_device, &ctx.format_passphrase)?;
    events.push(event(
        WorkflowLevel::Info,
        "Formatted loopback device with LUKS2 header.",
    ));

    write_crypttab_entry(&ctx.crypttab_path, &ctx.mapping_name, &ctx.loop_device)?;
    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Staged temporary crypttab entry at {} for mapping {}",
            ctx.crypttab_path.display(),
            ctx.mapping_name
        ),
    ));

    let sim_config = build_luks_simulation_config(
        config,
        &ctx.mapping_name,
        &key_path,
        &key_material,
        &cryptsetup_path,
        &ctx.crypttab_path,
        &mut events,
    );

    let provider = provider_builder(&sim_config)?;
    provider.enroll_mapping_key(&ctx.mapping_name, &ctx.format_passphrase, &key_path)?;
    events.push(event(
        WorkflowLevel::Success,
        "Enrolled staged key material into the simulated LUKS keyslot.",
    ));

    let options = UnlockOptions {
        strict_usb,
        ..UnlockOptions::default()
    };

    let mut bad_cfg = sim_config.clone();
    bad_cfg.usb.expected_sha256 = Some("ffffffff".to_string());
    let bad_service =
        LockchainService::new(Arc::new(bad_cfg), LuksKeyProvider::new(provider.clone()));
    match bad_service.unlock(&ctx.mapping_name, options.clone()) {
        Err(LockchainError::InvalidConfig(message)) if message.contains("usb.expected_sha256") => {
            events.push(event(
                WorkflowLevel::Success,
                "Checksum mismatch correctly blocked unlock (negative test).",
            ));
        }
        Err(err) => return Err(err),
        Ok(_) => {
            return Err(LockchainError::Provider(
                "checksum mismatch did not block unlock (negative test)".into(),
            ))
        }
    }

    if matches!(
        provider.mapping_state(&ctx.mapping_name)?,
        lockchain_provider::luks::LuksState::Active
    ) {
        return Err(LockchainError::Provider(
            "mapping became active during checksum-negative test; expected it to remain inactive"
                .into(),
        ));
    }

    let service = LockchainService::new(
        Arc::new(sim_config.clone()),
        LuksKeyProvider::new(provider.clone()),
    );
    let report = service.unlock_with_retry(&ctx.mapping_name, options)?;
    if report.already_unlocked {
        events.push(event(
            WorkflowLevel::Warn,
            "Mapping already active when self-test began; continuing verification.",
        ));
    } else {
        events.push(event(
            WorkflowLevel::Success,
            format!("Self-test unlock succeeded for {}.", report.encryption_root),
        ));
    }

    if !matches!(
        provider.mapping_state(&ctx.mapping_name)?,
        lockchain_provider::luks::LuksState::Active
    ) {
        return Err(LockchainError::Provider(
            "mapping did not report active after unlock; investigate cryptsetup output".into(),
        ));
    }

    close_mapping(&cryptsetup_path, &ctx.mapping_name)?;
    events.push(event(
        WorkflowLevel::Info,
        "Closed simulated mapping after unlock verification.",
    ));

    if matches!(
        provider.mapping_state(&ctx.mapping_name)?,
        lockchain_provider::luks::LuksState::Active
    ) {
        return Err(LockchainError::Provider(
            "mapping remained active after close; investigate cryptsetup output".into(),
        ));
    }

    ctx.cleanup();
    events.push(event(
        WorkflowLevel::Success,
        "Self-test completed; loopback volume dismantled.",
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

fn resolve_binary_path(
    configured: Option<&str>,
    defaults: &[&str],
    name: &str,
) -> LockchainResult<PathBuf> {
    if let Some(path) = configured {
        let candidate = PathBuf::from(path);
        if candidate.exists() {
            return Ok(candidate);
        }
        return Err(LockchainError::InvalidConfig(format!(
            "{name} binary configured at {} but missing",
            candidate.display()
        )));
    }

    if let Some(path) = find_in_path(name) {
        return Ok(path);
    }

    for candidate in defaults {
        let path = Path::new(candidate);
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }

    Err(LockchainError::InvalidConfig(format!(
        "unable to locate {name} binary; tried PATH and {:?}",
        defaults
    )))
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths).find_map(|dir| {
        let candidate = dir.join(binary);
        if candidate.exists() {
            Some(candidate)
        } else {
            None
        }
    })
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

struct LuksSimulationContext {
    _temp_dir: TempDir,
    image_path: PathBuf,
    crypttab_path: PathBuf,
    loop_device: String,
    mapping_name: String,
    cryptsetup_path: PathBuf,
    losetup_path: PathBuf,
    format_passphrase: Zeroizing<Vec<u8>>,
    cleaned: bool,
}

impl LuksSimulationContext {
    fn prepare(cryptsetup_path: &Path, losetup_path: &Path) -> LockchainResult<Self> {
        let temp_dir = TempDir::new().map_err(|err| LockchainError::Provider(err.to_string()))?;
        let image_path = temp_dir.path().join("lockchain-selftest-luks.img");
        let backing =
            File::create(&image_path).map_err(|err| LockchainError::Provider(err.to_string()))?;
        backing
            .set_len(64 * 1024 * 1024)
            .map_err(|err| LockchainError::Provider(err.to_string()))?;

        let mapping_name = format!(
            "lcst_{}",
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(8)
                .map(char::from)
                .collect::<String>()
                .to_lowercase()
        );
        let crypttab_path = temp_dir.path().join("crypttab");

        let loop_device = losetup_attach(losetup_path, &image_path)?;
        let passphrase = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .collect::<Vec<u8>>();

        Ok(Self {
            _temp_dir: temp_dir,
            image_path,
            crypttab_path,
            loop_device,
            mapping_name,
            cryptsetup_path: cryptsetup_path.to_path_buf(),
            losetup_path: losetup_path.to_path_buf(),
            format_passphrase: Zeroizing::new(passphrase),
            cleaned: false,
        })
    }

    fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        let _ = close_mapping(&self.cryptsetup_path, &self.mapping_name);
        let _ = Command::new(&self.losetup_path)
            .args(["-d", &self.loop_device])
            .status();
        self.cleaned = true;
    }
}

impl Drop for LuksSimulationContext {
    fn drop(&mut self) {
        if !self.cleaned {
            self.cleanup();
        }
    }
}

fn losetup_attach(binary: &Path, image_path: &Path) -> LockchainResult<String> {
    let image_arg = image_path.to_string_lossy();
    let output = run_exec(binary, &["--find", "--show", image_arg.as_ref()], None)?;
    if output.status == 0 {
        let loopdev = output.stdout.trim();
        if loopdev.is_empty() {
            return Err(LockchainError::Provider(
                "losetup returned empty loop device path".into(),
            ));
        }
        return Ok(loopdev.to_string());
    }

    Err(LockchainError::Provider(format!(
        "losetup failed: {}",
        output.stderr.trim()
    )))
}

fn luks_format(binary: &Path, device: &str, passphrase: &[u8]) -> LockchainResult<()> {
    let output = run_exec(
        binary,
        &[
            "luksFormat",
            "--type",
            "luks2",
            "--batch-mode",
            "--key-file",
            "-",
            device,
        ],
        Some(passphrase),
    )?;
    if output.status == 0 {
        return Ok(());
    }

    Err(LockchainError::Provider(format!(
        "cryptsetup luksFormat failed: {}",
        output.stderr.trim()
    )))
}

fn close_mapping(binary: &Path, name: &str) -> LockchainResult<()> {
    let mut output = run_exec(binary, &["close", name], None)?;
    if output.status != 0 && action_unsupported(&output) {
        output = run_exec(binary, &["luksClose", name], None)?;
    }
    if output.status == 0 {
        return Ok(());
    }

    let diagnostic = if output.stderr.trim().is_empty() {
        output.stdout.trim().to_ascii_lowercase()
    } else {
        output.stderr.trim().to_ascii_lowercase()
    };
    if diagnostic.contains("does not exist")
        || diagnostic.contains("doesn't exist")
        || diagnostic.contains("not active")
    {
        return Ok(());
    }

    Err(LockchainError::Provider(format!(
        "cryptsetup close failed: {}",
        diagnostic.trim()
    )))
}

fn write_crypttab_entry(path: &Path, mapping: &str, source: &str) -> LockchainResult<()> {
    let line = format!("{mapping} {source} none luks,noauto\n");
    std::fs::write(path, line).map_err(|err| LockchainError::Provider(err.to_string()))
}

fn build_luks_simulation_config(
    base: &LockchainConfig,
    mapping: &str,
    key_path: &Path,
    key_material: &[u8],
    cryptsetup_path: &Path,
    crypttab_path: &Path,
    events: &mut Vec<super::WorkflowEvent>,
) -> LockchainConfig {
    let mut cfg = base.clone();
    cfg.provider.r#type = ProviderKind::Luks;
    cfg.policy.targets = vec![mapping.to_string()];
    cfg.usb.key_hex_path = key_path.to_string_lossy().into_owned();
    if cfg.usb.expected_sha256.is_none() {
        cfg.usb.expected_sha256 = Some(hex::encode(Sha256::digest(key_material)));
        events.push(event(
            WorkflowLevel::Warn,
            "usb.expected_sha256 not configured; self-test will proceed with an ephemeral checksum, but you should persist the digest in config to enforce key identity."
        ));
    }
    cfg.luks.cryptsetup_path = Some(cryptsetup_path.to_string_lossy().into_owned());
    cfg.luks.crypttab_path = Some(crypttab_path.to_string_lossy().into_owned());
    cfg
}

#[derive(Debug)]
struct ExecOutput {
    stdout: String,
    stderr: String,
    status: i32,
}

fn run_exec(binary: &Path, args: &[&str], input: Option<&[u8]>) -> LockchainResult<ExecOutput> {
    let mut command = Command::new(binary);
    command.args(args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if input.is_some() {
        command.stdin(Stdio::piped());
    }

    let mut child = command
        .spawn()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    if let Some(payload) = input {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(payload)
                .map_err(|err| LockchainError::Provider(err.to_string()))?;
            let _ = stdin.flush();
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    Ok(ExecOutput {
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        status: output.status.code().unwrap_or(-1),
    })
}

fn action_unsupported(output: &ExecOutput) -> bool {
    let diagnostic = if output.stderr.trim().is_empty() {
        output.stdout.to_ascii_lowercase()
    } else {
        output.stderr.to_ascii_lowercase()
    };
    diagnostic.contains("unknown action")
        || diagnostic.contains("unknown command")
        || diagnostic.contains("invalid action")
        || diagnostic.contains("invalid command")
        || diagnostic.contains("unknown option")
}
