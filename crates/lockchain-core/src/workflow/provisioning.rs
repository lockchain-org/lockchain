//! Provisioning workflow that wipes, seeds, and configures the USB key token.

use super::{event, privilege::run_external, WorkflowEvent, WorkflowLevel, WorkflowReport};
use crate::config::{detect_binary_path, LockchainConfig, Usb, KNOWN_ZFS_PATHS};
use crate::error::{LockchainError, LockchainResult};
use crate::keyfile::{read_key_file, write_raw_key_file};
use crate::provider::ZfsProvider;
use pbkdf2::pbkdf2_hmac;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroizing;

const LOCKCHAIN_LABEL: &str = "LOCKCHAINKEY";
const STAGING_ROOT: &str = "/run/lockchain/media";
const PARTED_BINARIES: &[&str] = &["/sbin/parted", "/usr/sbin/parted", "/usr/bin/parted"];
const MKFS_BINARIES: &[&str] = &[
    "/sbin/mkfs.ext4",
    "/usr/sbin/mkfs.ext4",
    "/usr/bin/mkfs.ext4",
];
const BLKID_BINARIES: &[&str] = &["/sbin/blkid", "/usr/sbin/blkid", "/usr/bin/blkid"];
const LSBLK_BINARIES: &[&str] = &["/bin/lsblk", "/usr/bin/lsblk"];
const UDEVADM_BINARIES: &[&str] = &["/sbin/udevadm", "/usr/sbin/udevadm", "/usr/bin/udevadm"];
const MOUNT_BINARIES: &[&str] = &["/bin/mount", "/usr/bin/mount"];
const UMOUNT_BINARIES: &[&str] = &["/bin/umount", "/usr/bin/umount"];
const DRACUT_BINARIES: &[&str] = &["/usr/bin/dracut", "/usr/sbin/dracut"];
const UPDATE_INITRAMFS_BINARIES: &[&str] = &["/usr/sbin/update-initramfs"];
const LSINITRD_BINARIES: &[&str] = &["/usr/bin/lsinitrd", "/bin/lsinitrd"];
const INITRAMFS_HOOK_PATH: &str = "/etc/initramfs-tools/hooks/zz-lockchain";
const INITRAMFS_LOCAL_TOP_PATH: &str = "/etc/initramfs-tools/scripts/local-top/lockchain";
const PLACEHOLDER_DEVICE_LABEL: &str = "REPLACE_WITH_USB_LABEL";

/// Enumerated removable media device surfaced by discovery.
#[derive(Debug, Clone, Serialize)]
pub struct UsbCandidate {
    pub disk: String,
    pub device: String,
    pub label: Option<String>,
    pub model: Option<String>,
    pub serial: Option<String>,
    pub size: Option<String>,
    pub transport: Option<String>,
    pub mountpoint: Option<String>,
}

impl UsbCandidate {
    /// Render a concise human-readable summary for prompts and logs.
    pub fn describe(&self) -> String {
        let mut traits = Vec::new();

        if let Some(model) = self.model.as_deref() {
            if !model.is_empty() {
                traits.push(model.trim().to_string());
            }
        }
        if let Some(size) = self.size.as_deref() {
            if !size.is_empty() {
                traits.push(size.trim().to_string());
            }
        }
        if let Some(label) = self.label.as_deref() {
            if !label.is_empty() {
                traits.push(format!("label {}", label.trim()));
            }
        }
        if let Some(serial) = self.serial.as_deref() {
            if !serial.is_empty() {
                traits.push(format!("serial {}", serial.trim()));
            }
        }
        if let Some(bus) = self.transport.as_deref() {
            if !bus.is_empty() {
                traits.push(format!("bus {}", bus.trim()));
            }
        }
        if self.device != self.disk {
            traits.push(format!("disk {}", self.disk));
        }
        if let Some(mp) = self.mountpoint.as_deref() {
            if !mp.is_empty() {
                traits.push(format!("mounted {}", mp.trim()));
            }
        }

        if traits.is_empty() {
            self.device.clone()
        } else {
            format!("{} ({})", self.device, traits.join(", "))
        }
    }
}

/// Determines whether provisioning wipes the token or leaves it intact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForgeMode {
    Standard,
    Safe,
}

/// Caller-provided knobs that influence USB selection, mounting, and post-work.
#[derive(Debug, Clone)]
pub struct ProvisionOptions {
    pub usb_device: Option<String>,
    pub mountpoint: Option<PathBuf>,
    pub key_filename: Option<String>,
    pub passphrase: Option<String>,
    pub force_wipe: bool,
    pub rebuild_initramfs: bool,
}

impl Default for ProvisionOptions {
    fn default() -> Self {
        Self {
            usb_device: None,
            mountpoint: None,
            key_filename: None,
            passphrase: None,
            force_wipe: false,
            rebuild_initramfs: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitramfsFlavor {
    Dracut,
    InitramfsTools,
}

/// Prepare the USB token, generate new key material, and refresh integration assets.
pub fn forge_key<P: ZfsProvider<Error = LockchainError> + Clone>(
    config: &mut LockchainConfig,
    provider: &P,
    dataset: &str,
    mode: ForgeMode,
    mut options: ProvisionOptions,
) -> LockchainResult<WorkflowReport> {
    let mut events = Vec::new();

    if !config.contains_dataset(dataset) {
        return Err(LockchainError::DatasetNotConfigured(dataset.to_string()));
    }

    let encryption_root = provider.encryption_root(dataset)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Encryption root resolved to {encryption_root}"),
    ));

    let locked_descendants = provider.locked_descendants(&encryption_root)?;
    if locked_descendants.iter().any(|ds| ds == &encryption_root) {
        return Err(LockchainError::Provider(format!(
            "encryption root {encryption_root} is still locked; unlock before forging a new key"
        )));
    }

    let usb_device = resolve_usb_device(&options, config)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Using USB device {usb_device}"),
    ));

    let (usb_disk, usb_partition) = derive_device_layout(&usb_device)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Disk {usb_disk} partition {usb_partition} selected"),
    ));

    let safe_mode = matches!(mode, ForgeMode::Safe);

    if options.force_wipe || !safe_mode {
        wipe_usb_token(&usb_disk, &usb_partition)?;
        events.push(event(
            WorkflowLevel::Success,
            format!(
                "Reinitialised {} with label {}",
                usb_partition, LOCKCHAIN_LABEL
            ),
        ));
    } else {
        ensure_partition_label(&usb_partition)?;
        events.push(event(
            WorkflowLevel::Info,
            format!(
                "Safe mode: existing filesystem on {} validated for label {}",
                usb_partition, LOCKCHAIN_LABEL
            ),
        ));
    }

    settle_udev()?;

    let filename = options
        .key_filename
        .clone()
        .unwrap_or_else(|| config.usb.device_key_path.clone());
    let mountpoint = options.mountpoint.clone().unwrap_or_else(|| {
        let label_dir = config
            .usb
            .device_label
            .as_deref()
            .map(str::trim)
            .filter(|label| !label.is_empty() && !label_is_placeholder(label))
            .unwrap_or(LOCKCHAIN_LABEL);
        PathBuf::from(STAGING_ROOT).join(label_dir)
    });
    let key_path = mountpoint.join(&filename);

    fs::create_dir_all(&mountpoint)?;

    let mount_guard = MountGuard::mount(&usb_partition, &mountpoint)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Mounted {} at {}", usb_partition, mountpoint.display()),
    ));

    let mut key_material = vec![0u8; 32];
    OsRng.fill_bytes(&mut key_material);
    write_key_with_remount(&key_path, &key_material, &mountpoint, &mut events)?;
    if fs::metadata(&key_path)?.len() != 32 {
        return Err(LockchainError::Provider(format!(
            "generated key at {} is not 32 bytes; aborting provisioning",
            key_path.display()
        )));
    }
    events.push(event(
        WorkflowLevel::Success,
        format!("Wrote key material to {}", key_path.display()),
    ));

    // Primary key location used at boot: the actual mountpoint in use now.
    let dest_path = mountpoint.join(&filename);
    // Keep a host-side reference that the USB watcher and tuning can read while the token is mounted.
    let host_token_path = dest_path.clone();
    write_key_with_remount(&host_token_path, &key_material, &mountpoint, &mut events)?;
    if fs::metadata(&host_token_path)?.len() != 32 {
        return Err(LockchainError::Provider(format!(
            "destination key at {} is not 32 bytes; aborting provisioning",
            host_token_path.display()
        )));
    }
    events.push(event(
        WorkflowLevel::Info,
        format!("Wrote key material to {}", host_token_path.display()),
    ));

    let recovery_key_hex = hex::encode(&key_material);
    let digest = hex::encode(Sha256::digest(&key_material));

    change_encryption_key(&encryption_root, &dest_path, &mut events)?;

    configure_fallback_passphrase(
        &mut events,
        config,
        options.passphrase.take(),
        &key_material,
    )?;
    events.push(event(
        WorkflowLevel::Security,
        "Recovery key generated. Record it securely before acknowledging the prompt.",
    ));

    let device_uuid = detect_partition_uuid(&usb_partition).ok().flatten();

    update_config(
        config,
        dataset,
        dest_path.clone(),
        filename.clone(),
        digest.clone(),
        device_uuid.clone(),
    )?;
    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Config updated with key location {} and checksum {}",
            dest_path.display(),
            digest
        ),
    ));

    let dest_key_path = dest_path.clone();
    let datasets: Vec<String> = config
        .policy
        .datasets
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    if datasets.is_empty() {
        return Err(LockchainError::InvalidConfig(
            "policy.datasets must contain at least one dataset before installing initramfs assets"
                .into(),
        ));
    }

    let flavor = detect_initramfs_flavor()?;
    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Initramfs tooling detected: {}.",
            match flavor {
                InitramfsFlavor::Dracut => "dracut",
                InitramfsFlavor::InitramfsTools => "initramfs-tools",
            }
        ),
    ));

    match flavor {
        InitramfsFlavor::Dracut => install_dracut_module(
            &mountpoint.to_string_lossy(),
            &dest_key_path,
            filename.as_str(),
            Some(&digest),
            device_uuid.as_deref(),
            &datasets,
            &mut events,
        )?,
        InitramfsFlavor::InitramfsTools => install_initramfs_tools_hooks(
            dest_key_path.parent().unwrap_or(&mountpoint),
            &dest_key_path,
            Some(&digest),
            config
                .usb
                .device_label
                .as_deref()
                .unwrap_or(LOCKCHAIN_LABEL),
            &mut events,
        )?,
    }
    set_keylocation_property(&encryption_root, &dest_key_path, &mut events)?;
    verify_key_load(
        &encryption_root,
        &dest_key_path,
        Some(&key_path),
        &mut events,
    )?;
    mount_guard.sync()?; // flush writes before unmount
    drop(mount_guard); // unmount
    if options.rebuild_initramfs {
        rebuild_initramfs(&mut events, flavor)?;
        audit_initramfs(&mut events, flavor)?;
    } else {
        events.push(event(
            WorkflowLevel::Warn,
            "Initramfs rebuild skipped (rebuild=false). Ensure loader assets are regenerated manually.",
        ));
    }

    Ok(WorkflowReport {
        title: format!("Forged new key for {dataset}"),
        events,
        recovery_key: Some(recovery_key_hex),
    })
}

/// Ensure the encryption root points at the installed key path for headless unlock.
pub(crate) fn set_keylocation_property(
    encryption_root: &str,
    dest_path: &Path,
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    let keylocation = format!("file://{}", dest_path.display());
    let zfs_binary = detect_binary_path(KNOWN_ZFS_PATHS)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/zfs"));

    let status = Command::new(&zfs_binary)
        .args([
            "set",
            &format!("keylocation={keylocation}"),
            encryption_root,
        ])
        .status()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    if status.success() {
        events.push(event(
            WorkflowLevel::Info,
            format!(
                "Set keylocation for {} to {}.",
                encryption_root, keylocation
            ),
        ));
        Ok(())
    } else {
        events.push(event(
            WorkflowLevel::Warn,
            format!(
                "Failed to set keylocation for {}; ensure keylocation points at {}.",
                encryption_root, keylocation
            ),
        ));
        Ok(())
    }
}

/// Confirm that the configured keylocation can load the key and that keystatus reports available.
fn verify_key_load(
    encryption_root: &str,
    dest_path: &Path,
    load_path_override: Option<&Path>,
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    let zfs_binary = detect_binary_path(KNOWN_ZFS_PATHS)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/zfs"));

    // If the key is already loaded, skip the explicit load-key call to avoid benign errors.
    let pre_status = Command::new(&zfs_binary)
        .args(["get", "-H", "-o", "value", "keystatus", encryption_root])
        .output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;
    if pre_status.status.success() {
        let status_str = String::from_utf8_lossy(&pre_status.stdout)
            .trim()
            .to_string();
        if status_str.eq_ignore_ascii_case("available") {
            events.push(event(
                WorkflowLevel::Info,
                format!(
                    "keystatus for {} is already available; load-key validation skipped.",
                    encryption_root
                ),
            ));
            return Ok(());
        }
    }

    let load_path = load_path_override
        .filter(|p| p.exists())
        .unwrap_or(dest_path);
    let load_location = format!("file://{}", load_path.display());

    let status = Command::new(&zfs_binary)
        .args(["load-key", "-L", &load_location, encryption_root])
        .status()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    if status.success() {
        events.push(event(
            WorkflowLevel::Success,
            format!(
                "Validated key load for {} using {}; keystatus will be checked next.",
                encryption_root, load_location
            ),
        ));
    } else {
        events.push(event(
            WorkflowLevel::Warn,
            format!(
                "zfs load-key validation for {} returned {:?}; ensure the key is reachable at {}.",
                encryption_root,
                status.code(),
                load_location
            ),
        ));
    }

    let output = Command::new(&zfs_binary)
        .args(["get", "-H", "-o", "value", "keystatus", encryption_root])
        .output()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    if output.status.success() {
        let status_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if status_str.eq_ignore_ascii_case("available") {
            events.push(event(
                WorkflowLevel::Success,
                format!("keystatus for {} reports available.", encryption_root),
            ));
        } else {
            events.push(event(
                WorkflowLevel::Warn,
                format!(
                    "keystatus for {} is {}; rerun tuning if this is unexpected.",
                    encryption_root, status_str
                ),
            ));
        }
    } else {
        events.push(event(
            WorkflowLevel::Warn,
            format!(
                "Unable to read keystatus for {}; zfs get exited with {:?}.",
                encryption_root,
                output.status.code()
            ),
        ));
    }

    Ok(())
}

/// Determine which block device to operate on, using CLI options or config hints.
fn resolve_usb_device(
    options: &ProvisionOptions,
    config: &LockchainConfig,
) -> LockchainResult<String> {
    if let Some(selector) = options.usb_device.as_ref() {
        let trimmed = selector.trim();
        if !trimmed.eq_ignore_ascii_case("auto") {
            if let Some(candidate) = usb_candidate_from_selector(trimmed)? {
                return Ok(candidate.device);
            }
            return Ok(trimmed.to_string());
        }
    }
    if let Some(label) = config.usb.device_label.as_ref() {
        if !label_is_placeholder(label) {
            if let Some(device) = device_from_label(label)? {
                return Ok(device);
            }
        }
    }
    if let Some(uuid) = config.usb.device_uuid.as_ref() {
        if let Some(device) = device_from_uuid(uuid)? {
            return Ok(device);
        }
    }

    let candidates = discover_usb_candidates().map_err(|err| {
        LockchainError::InvalidConfig(format!(
            "USB device not specified and discovery failed: {err}"
        ))
    })?;

    match candidates.len() {
        0 => Err(LockchainError::InvalidConfig(
            "USB device not specified; set usb.device_label (or usb.device_uuid) in the configuration, pass device=/dev/sdX, or attach removable media so discovery can select a target."
                .to_string(),
        )),
        1 => Ok(candidates[0].device.clone()),
        _ => Err(LockchainError::InvalidConfig(
            render_usb_selection_prompt(&candidates),
        )),
    }
}

/// Probe blkid for a device matching the requested filesystem label.
fn device_from_label(label: &str) -> LockchainResult<Option<String>> {
    for candidate in BLKID_BINARIES {
        if Path::new(candidate).exists() {
            let output =
                run_external(&[candidate], &[OsString::from("-L"), OsString::from(label)])?;
            if output.status.success() {
                let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !device.is_empty() {
                    return Ok(Some(device));
                }
            }
        }
    }
    Ok(None)
}

fn label_is_placeholder(label: &str) -> bool {
    let trimmed = label.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case(PLACEHOLDER_DEVICE_LABEL)
}

/// Probe blkid for a partition matching the provided UUID.
fn device_from_uuid(uuid: &str) -> LockchainResult<Option<String>> {
    for candidate in BLKID_BINARIES {
        if Path::new(candidate).exists() {
            let output = run_external(&[candidate], &[OsString::from("-U"), OsString::from(uuid)])?;
            if output.status.success() {
                let device = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !device.is_empty() {
                    return Ok(Some(device));
                }
            }
        }
    }
    Ok(None)
}

/// Present the available removable media in a CLI-friendly prompt.
pub fn render_usb_selection_prompt(candidates: &[UsbCandidate]) -> String {
    if candidates.is_empty() {
        return "No removable USB storage detected; attach the key or specify device=/dev/sdX."
            .to_string();
    }

    let mut lines = vec![
        "Multiple removable devices detected. Choose with device=<index> or device=/dev/sdX:"
            .to_string(),
    ];
    for (index, candidate) in candidates.iter().enumerate() {
        lines.push(format!("  [{}] {}", index + 1, candidate.describe()));
    }
    lines.push("Example: device=1 or device=/dev/sdb1".to_string());
    lines.join("\n")
}

/// Return the candidate referenced by an index-based selector, if applicable.
pub fn usb_candidate_from_selector(selector: &str) -> LockchainResult<Option<UsbCandidate>> {
    let trimmed = selector.trim();
    let normalized = trimmed.strip_prefix('#').unwrap_or(trimmed);
    if normalized.is_empty() {
        return Err(LockchainError::InvalidConfig(
            "device selector provided but empty".to_string(),
        ));
    }

    if normalized.chars().all(|ch| ch.is_ascii_digit())
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_digit() || ch == '#' || ch.is_whitespace())
    {
        let index = normalized.parse::<usize>().map_err(|_| {
            LockchainError::InvalidConfig(format!(
                "device selector `{selector}` is not a valid numeric index"
            ))
        })?;
        if index == 0 {
            return Err(LockchainError::InvalidConfig(
                "device index must start at 1".into(),
            ));
        }
        let candidates = discover_usb_candidates().map_err(|err| {
            LockchainError::InvalidConfig(format!("unable to enumerate removable devices: {err}"))
        })?;
        if candidates.is_empty() {
            return Err(LockchainError::InvalidConfig(
                "device index requested but no removable media detected".into(),
            ));
        }
        if index > candidates.len() {
            return Err(LockchainError::InvalidConfig(format!(
                "device index {index} out of range ({} candidates).\n{}",
                candidates.len(),
                render_usb_selection_prompt(&candidates)
            )));
        }
        return Ok(Some(candidates[index - 1].clone()));
    }

    Ok(None)
}

/// Enumerate removable media candidates available on the host.
pub fn discover_usb_candidates() -> LockchainResult<Vec<UsbCandidate>> {
    let args = vec![
        OsString::from("--json"),
        OsString::from("-o"),
        OsString::from("NAME,PATH,TYPE,RM,SIZE,MODEL,SERIAL,LABEL,TRAN,MOUNTPOINT"),
    ];
    let output = run_external(LSBLK_BINARIES, &args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(LockchainError::Provider(format!(
            "lsblk discovery failed: {stderr}"
        )));
    }

    let decoded: LsblkResponse = serde_json::from_slice(&output.stdout).map_err(|err| {
        LockchainError::Provider(format!("failed to parse lsblk JSON output: {err}"))
    })?;

    let mut collected = Vec::new();
    for device in decoded.blockdevices {
        collect_usb_candidates(&device, &mut collected);
    }
    collected.sort_by(|a, b| a.device.cmp(&b.device));
    collected.dedup_by(|lhs, rhs| lhs.device == rhs.device);
    Ok(collected)
}

/// Configure or disable the fallback passphrase using existing key material on disk.
pub fn update_fallback_passphrase(
    config: &mut LockchainConfig,
    passphrase: Option<String>,
) -> LockchainResult<Vec<WorkflowEvent>> {
    let mut events = Vec::new();
    let key_path = config.key_hex_path();
    let (key, converted) = read_key_file(&key_path).map_err(|err| {
        LockchainError::InvalidConfig(format!(
            "Unable to load key material from {}: {}",
            key_path.display(),
            err
        ))
    })?;
    if converted {
        write_raw_key_file(&key_path, &key)?;
    }
    if key.len() != 32 {
        return Err(LockchainError::InvalidConfig(format!(
            "Key material must be 32 raw bytes; found {} bytes in {}",
            key.len(),
            key_path.display()
        )));
    }

    configure_fallback_passphrase(&mut events, config, passphrase, &key)?;
    config.save()?;
    Ok(events)
}

#[derive(Debug, Deserialize)]
struct LsblkResponse {
    #[serde(default)]
    blockdevices: Vec<LsblkNode>,
}

#[derive(Debug, Deserialize)]
struct LsblkNode {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(rename = "type")]
    #[serde(default)]
    device_type: Option<String>,
    #[serde(default)]
    rm: Option<bool>,
    #[serde(default)]
    size: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    tran: Option<String>,
    #[serde(default)]
    mountpoint: Option<String>,
    #[serde(default)]
    children: Vec<LsblkNode>,
}

fn collect_usb_candidates(node: &LsblkNode, out: &mut Vec<UsbCandidate>) {
    if is_removable_disk(node) {
        if let Some(disk_path) = node_path(node) {
            let first_partition = node
                .children
                .iter()
                .find(|child| child.device_type.as_deref() == Some("part"));

            let device_path = first_partition
                .and_then(node_path)
                .unwrap_or_else(|| disk_path.clone());

            let label = first_partition
                .and_then(|child| sanitize(child.label.clone()))
                .or_else(|| sanitize(node.label.clone()));

            let mountpoint = first_partition
                .and_then(|child| sanitize(child.mountpoint.clone()))
                .or_else(|| sanitize(node.mountpoint.clone()));

            out.push(UsbCandidate {
                disk: disk_path,
                device: device_path,
                label,
                model: sanitize(node.model.clone()),
                serial: sanitize(node.serial.clone()),
                size: sanitize(node.size.clone()),
                transport: sanitize(node.tran.clone()),
                mountpoint,
            });
        }
    }

    for child in &node.children {
        collect_usb_candidates(child, out);
    }
}

fn is_removable_disk(node: &LsblkNode) -> bool {
    if node.device_type.as_deref() != Some("disk") {
        return false;
    }
    if node.rm.unwrap_or(false) {
        return true;
    }
    matches!(
        node.tran
            .as_deref()
            .map(|tran| tran.eq_ignore_ascii_case("usb")),
        Some(true)
    )
}

fn node_path(node: &LsblkNode) -> Option<String> {
    if let Some(path) = node.path.as_ref() {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    node.name
        .as_ref()
        .map(|name| format!("/dev/{}", name.trim()))
}

fn sanitize(value: Option<String>) -> Option<String> {
    value.and_then(|val| {
        let trimmed = val.trim().to_string();
        if trimmed.is_empty() || trimmed == "null" {
            None
        } else {
            Some(trimmed)
        }
    })
}

/// Work out the disk/partition pair we should operate on for the target device.
fn derive_device_layout(device: &str) -> LockchainResult<(String, String)> {
    let device_path = Path::new(device);
    if !device_path.exists() {
        return Err(LockchainError::InvalidConfig(format!(
            "device {device} not found"
        )));
    }

    let block_type = query_block_info(device, "TYPE")?;
    match block_type.as_str() {
        "disk" => {
            if let Some(existing) = existing_partition_for_disk(device)? {
                Ok((device.to_string(), existing))
            } else {
                Ok((device.to_string(), predict_partition_name(device)))
            }
        }
        "part" => {
            let parent = query_block_info(device, "PKNAME")?;
            if parent.is_empty() {
                Err(LockchainError::InvalidConfig(format!(
                    "unable to resolve parent disk for {device}"
                )))
            } else {
                Ok((format!("/dev/{}", parent.trim()), device.to_string()))
            }
        }
        other => Err(LockchainError::InvalidConfig(format!(
            "unsupported block type {other} for {device}"
        ))),
    }
}

/// Run `lsblk` for a single field and normalise the output.
fn query_block_info(device: &str, field: &str) -> LockchainResult<String> {
    let args = vec![
        OsString::from("-no"),
        OsString::from(field),
        OsString::from(device),
    ];
    let output = run_external(LSBLK_BINARIES, &args)?;
    if !output.status.success() {
        return Err(LockchainError::Provider(format!(
            "lsblk -no {} {} failed: {}",
            field,
            device,
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Look for an existing partition on `disk` we can reuse.
fn existing_partition_for_disk(disk: &str) -> LockchainResult<Option<String>> {
    let args = vec![
        OsString::from("-P"),
        OsString::from("-nrpo"),
        OsString::from("PATH,TYPE"),
        OsString::from(disk),
    ];
    let output = run_external(LSBLK_BINARIES, &args)?;
    if !output.status.success() {
        return Ok(None);
    }

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut path = None;
        let mut kind = None;
        for part in line.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                let trimmed = value.trim_matches('"').to_string();
                match key {
                    "PATH" => path = Some(trimmed),
                    "TYPE" => kind = Some(trimmed),
                    _ => {}
                }
            }
        }
        if matches!(kind.as_deref(), Some("part")) {
            if let Some(path) = path {
                if Path::new(&path).exists() {
                    return Ok(Some(path));
                }
            }
        }
    }

    Ok(None)
}

/// Predict the first partition path a fresh GPT layout will produce.
fn predict_partition_name(disk: &str) -> String {
    let suffix_is_digit = Path::new(disk)
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|n| n.chars().last())
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false);

    if suffix_is_digit {
        format!("{disk}p1")
    } else {
        format!("{disk}1")
    }
}

/// Verify a partition already bears the expected Lockchain filesystem label.
fn ensure_partition_label(partition: &str) -> LockchainResult<()> {
    let args = vec![
        OsString::from("-s"),
        OsString::from("LABEL"),
        OsString::from("-o"),
        OsString::from("value"),
        OsString::from(partition),
    ];
    let output = run_external(BLKID_BINARIES, &args)?;
    if !output.status.success() {
        return Err(LockchainError::InvalidConfig(format!(
            "unable to read label for {partition}: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let label = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if label != LOCKCHAIN_LABEL {
        return Err(LockchainError::InvalidConfig(format!(
            "partition {partition} bears label {label}; expected {LOCKCHAIN_LABEL}"
        )));
    }
    Ok(())
}

/// Repartition and format the USB device with a fresh ext4 filesystem.
fn wipe_usb_token(disk: &str, partition: &str) -> LockchainResult<()> {
    dismantle_mounts(disk)?;
    dismantle_mounts(partition)?;

    run_external(
        PARTED_BINARIES,
        &[
            OsString::from("-s"),
            OsString::from(disk),
            OsString::from("mklabel"),
            OsString::from("gpt"),
        ],
    )?;
    run_external(
        PARTED_BINARIES,
        &[
            OsString::from("-s"),
            OsString::from(disk),
            OsString::from("mkpart"),
            OsString::from("LOCKCHAIN_PART"),
            OsString::from("ext4"),
            OsString::from("1MiB"),
            OsString::from("100%"),
        ],
    )?;
    settle_udev()?;
    run_external(
        MKFS_BINARIES,
        &[
            OsString::from("-F"),
            OsString::from("-L"),
            OsString::from(LOCKCHAIN_LABEL),
            OsString::from(partition),
        ],
    )?;
    Ok(())
}

/// Give udev time to notice the new partition layout before we continue.
fn settle_udev() -> LockchainResult<()> {
    let result = run_external(UDEVADM_BINARIES, &[OsString::from("settle")]);
    if let Err(err) = result {
        return Err(LockchainError::Provider(format!(
            "udevadm settle failed: {err}"
        )));
    }
    Ok(())
}

/// Unmount any existing mountpoints tied to `target`.
fn dismantle_mounts(target: &str) -> LockchainResult<()> {
    let args = vec![
        OsString::from("-nrpo"),
        OsString::from("NAME,MOUNTPOINT"),
        OsString::from(target),
    ];
    let output = run_external(LSBLK_BINARIES, &args)?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut parts = line.split_whitespace();
        let name = parts.next();
        let mount = parts.next();
        if let (Some(_name), Some(mountpoint)) = (name, mount) {
            if !mountpoint.trim().is_empty() {
                run_external(UMOUNT_BINARIES, &[OsString::from(mountpoint)])?;
            }
        }
    }
    Ok(())
}

/// Capture the partition UUID so the daemon can detect the token later.
fn detect_partition_uuid(partition: &str) -> LockchainResult<Option<String>> {
    let args = vec![
        OsString::from("-s"),
        OsString::from("UUID"),
        OsString::from("-o"),
        OsString::from("value"),
        OsString::from(partition),
    ];
    let output = run_external(BLKID_BINARIES, &args)?;
    if !output.status.success() {
        return Ok(None);
    }
    let uuid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if uuid.is_empty() {
        Ok(None)
    } else {
        Ok(Some(uuid))
    }
}

/// Optionally seed fallback passphrase material based on supplied input.
fn configure_fallback_passphrase(
    events: &mut Vec<WorkflowEvent>,
    config: &mut LockchainConfig,
    passphrase: Option<String>,
    key_material: &[u8],
) -> LockchainResult<()> {
    if let Some(passphrase) = passphrase {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut derived = Zeroizing::new(vec![0u8; key_material.len()]);
        pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, 250_000, &mut derived);

        let xor: Vec<u8> = key_material
            .iter()
            .zip(derived.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        config.fallback.enabled = true;
        config.fallback.passphrase_salt = Some(hex::encode(salt));
        config.fallback.passphrase_xor = Some(hex::encode(xor));
        config.fallback.passphrase_iters = 250_000;
        events.push(event(
            WorkflowLevel::Security,
            "Fallback passphrase material generated.",
        ));
    } else {
        config.fallback.enabled = false;
        config.fallback.passphrase_salt = None;
        config.fallback.passphrase_xor = None;
        events.push(event(WorkflowLevel::Info, "Fallback passphrase disabled."));
    }
    Ok(())
}

/// Persist the new key metadata and sane defaults back into the config file.
fn update_config(
    config: &mut LockchainConfig,
    dataset: &str,
    dest_key_path: PathBuf,
    device_key_filename: String,
    checksum: String,
    device_uuid: Option<String>,
) -> LockchainResult<()> {
    if !config.policy.datasets.iter().any(|entry| entry == dataset) {
        config.policy.datasets.push(dataset.to_string());
    }

    let file_name = device_key_filename;
    let device_label = config
        .usb
        .device_label
        .clone()
        .filter(|label| !label_is_placeholder(label))
        .unwrap_or_else(|| LOCKCHAIN_LABEL.to_string());

    config.usb = Usb {
        key_hex_path: dest_key_path.to_string_lossy().into_owned(),
        host_backup_path: None,
        expected_sha256: Some(checksum),
        device_label: Some(device_label),
        device_uuid,
        device_key_path: file_name,
        mount_timeout_secs: config.usb.mount_timeout_secs.max(10),
    };

    if config.policy.binary_path.is_none() {
        config.policy.binary_path = Some("/usr/local/bin/lockchain-cli".to_string());
    }

    if config.policy.zfs_path.is_none() {
        config.policy.zfs_path = Some("/usr/sbin/zfs".to_string());
    }

    if config.policy.zpool_path.is_none() {
        config.policy.zpool_path = Some("/usr/sbin/zpool".to_string());
    }

    if config.fallback.askpass_path.is_none() {
        config.fallback.askpass_path = Some("/usr/bin/systemd-ask-password".to_string());
    }

    config.save()?;
    Ok(())
}

/// RAII helper that unmounts the USB device when dropped.
struct MountGuard {
    mountpoint: PathBuf,
}

impl MountGuard {
    /// Mount the partition and return a guard that unmounts on drop.
    fn mount(partition: &str, mountpoint: &Path) -> LockchainResult<Self> {
        let mountpoint_str = mountpoint.to_string_lossy().into_owned();
        run_external(
            MOUNT_BINARIES,
            &[
                OsString::from("-o"),
                OsString::from("defaults"),
                OsString::from(partition),
                OsString::from(mountpoint_str),
            ],
        )?;
        Ok(Self {
            mountpoint: mountpoint.to_path_buf(),
        })
    }

    /// Flush pending writes to disk before unmounting.
    fn sync(&self) -> LockchainResult<()> {
        if let Err(err) = Command::new("sync").status() {
            return Err(LockchainError::Provider(err.to_string()));
        }
        Ok(())
    }
}

/// Rotate the dataset key material to the freshly generated raw key.
fn change_encryption_key(
    encryption_root: &str,
    key_path: &Path,
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    let keylocation = format!("file://{}", key_path.display());
    let zfs_binary = detect_binary_path(KNOWN_ZFS_PATHS)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/usr/sbin/zfs"));

    let status = Command::new(&zfs_binary)
        .args([
            "change-key",
            "-o",
            "keyformat=raw",
            "-o",
            &format!("keylocation={keylocation}"),
            encryption_root,
        ])
        .status()
        .map_err(|err| LockchainError::Provider(err.to_string()))?;

    if status.success() {
        events.push(event(
            WorkflowLevel::Success,
            format!(
                "Rotated encryption key for {} to raw key at {}.",
                encryption_root, keylocation
            ),
        ));
        Ok(())
    } else {
        Err(LockchainError::Provider(format!(
            "zfs change-key failed for {} (status {:?})",
            encryption_root,
            status.code()
        )))
    }
}

/// Write key material to the target path, remounting the token rw if another process mounted it ro.
fn write_key_with_remount(
    dest: &Path,
    key: &[u8],
    mountpoint: &Path,
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    match write_raw_key_file(dest, key) {
        Ok(_) => Ok(()),
        Err(err) => {
            let is_readonly = match &err {
                LockchainError::Io(io_err) => {
                    io_err.kind() == io::ErrorKind::PermissionDenied
                        || io_err.raw_os_error() == Some(30) // EROFS
                        || io_err
                            .to_string()
                            .to_lowercase()
                            .contains("read-only file system")
                }
                _ => false,
            };

            if is_readonly {
                let status = Command::new("mount")
                    .arg("-o")
                    .arg("remount,rw,nosuid,nodev,noexec")
                    .arg(mountpoint)
                    .status();
                if matches!(status, Ok(s) if s.success()) {
                    write_raw_key_file(dest, key)?;
                    events.push(event(
                        WorkflowLevel::Info,
                        format!(
                            "Remounted {} rw to write key material (fs was read-only).",
                            mountpoint.display()
                        ),
                    ));
                    Ok(())
                } else {
                    Err(LockchainError::Provider(format!(
                        "Token at {} mounted read-only; remount failed, cannot write key.",
                        mountpoint.display()
                    )))
                }
            } else {
                Err(err)
            }
        }
    }
}

impl Drop for MountGuard {
    fn drop(&mut self) {
        let _ = run_external(
            UMOUNT_BINARIES,
            &[OsString::from(
                self.mountpoint.to_string_lossy().into_owned(),
            )],
        );
    }
}

/// Stage the dracut hook and systemd drop-ins that load the key during boot.
pub(crate) fn install_dracut_module(
    mountpoint: &str,
    dest_path: &Path,
    key_filename: &str,
    checksum: Option<&str>,
    token_uuid: Option<&str>,
    datasets: &[String],
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    let ctx = DracutContext {
        mountpoint: mountpoint.to_string(),
        dest_path: dest_path.to_string_lossy().into_owned(),
        key_filename: key_filename.to_string(),
        checksum: checksum.map(|s| s.to_string()),
        token_uuid: token_uuid.map(|s| s.to_string()),
        datasets: datasets.to_vec(),
    };
    let module = DracutModule::install(&ctx)?;
    events.push(event(
        WorkflowLevel::Info,
        format!("Dracut module installed at {}", module.root.display()),
    ));
    Ok(())
}

fn detect_initramfs_flavor() -> LockchainResult<InitramfsFlavor> {
    if DRACUT_BINARIES
        .iter()
        .any(|candidate| Path::new(candidate).exists())
    {
        return Ok(InitramfsFlavor::Dracut);
    }

    if UPDATE_INITRAMFS_BINARIES
        .iter()
        .any(|candidate| Path::new(candidate).exists())
    {
        return Ok(InitramfsFlavor::InitramfsTools);
    }

    Err(LockchainError::Provider(
        "neither dracut nor initramfs-tools detected; cannot refresh initramfs assets".into(),
    ))
}

fn install_initramfs_tools_hooks(
    mountpoint: &Path,
    key_path: &Path,
    checksum: Option<&str>,
    token_label: &str,
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    let hook_path = Path::new(INITRAMFS_HOOK_PATH);
    if let Some(parent) = hook_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let hook_content = r#"#!/bin/sh
set -e

. /usr/share/initramfs-tools/hook-functions

for bin in zfs blkid mount umount mountpoint sha256sum stat; do
    if command -v "$bin" >/dev/null 2>&1; then
        copy_exec "$(command -v "$bin")"
    fi
done
"#;
    fs::write(hook_path, hook_content)?;
    fs::set_permissions(hook_path, fs::Permissions::from_mode(0o755))?;

    let local_top_path = Path::new(INITRAMFS_LOCAL_TOP_PATH);
    if let Some(parent) = local_top_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mountpoint_str = mountpoint.to_string_lossy();
    let key_path_str = key_path.to_string_lossy();
    let checksum_str = checksum.unwrap_or("").to_string();

    let local_top_content = format!(
        r#"#!/bin/sh
set -e

PREREQ="zfs"

prereqs() {{
    echo "$PREREQ"
}}

case "$1" in
    prereqs)
        prereqs
        exit 0
        ;;
esac

TOKEN_LABEL="{label}"
MOUNTPOINT="{mountpoint}"
KEY_PATH="{key_path}"
KEY_SHA256="{checksum}"
MAX_WAIT=30
SLEEP_INTERVAL=1

wait_for_device() {{
    local elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if blkid -L "$TOKEN_LABEL" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$SLEEP_INTERVAL"
        elapsed=$((elapsed + SLEEP_INTERVAL))
    done
    return 1
}}

wait_for_key() {{
    local elapsed=0
    while [ "$elapsed" -lt "$MAX_WAIT" ]; do
        if [ -f "$KEY_PATH" ]; then
            return 0
        fi
        sleep "$SLEEP_INTERVAL"
        elapsed=$((elapsed + SLEEP_INTERVAL))
    done
    return 1
}}

if ! wait_for_device; then
    echo "lockchain: token $TOKEN_LABEL not detected within ${{MAX_WAIT}}s; deferring to native prompts." >&2
    exit 0
fi

mkdir -p "$MOUNTPOINT"
DEVICE="$(blkid -L "$TOKEN_LABEL" 2>/dev/null || true)"
if [ -z "$DEVICE" ]; then
    echo "lockchain: token not detected; skipping auto-unlock" >&2
    exit 0
fi

if mountpoint -q "$MOUNTPOINT"; then
    :
elif ! mount -o ro,nosuid,nodev,noexec "$DEVICE" "$MOUNTPOINT"; then
    echo "lockchain: unable to mount token at $MOUNTPOINT" >&2
    exit 0
fi

if ! wait_for_key; then
    echo "lockchain: key file $KEY_PATH not detected within ${{MAX_WAIT}}s; relying on native prompts." >&2
    exit 0
fi

size=$(stat -c '%s' "$KEY_PATH" 2>/dev/null || echo 0)
if [ "$size" -ne 32 ]; then
    echo "lockchain: key file must be 32 bytes (found $size); deferring to native prompts." >&2
    exit 0
fi

if [ -n "$KEY_SHA256" ]; then
    actual=$(sha256sum "$KEY_PATH" | awk '{{print $1}}' | tr 'A-Z' 'a-z')
    expected=$(printf '%s' "$KEY_SHA256" | tr 'A-Z' 'a-z')
    if [ "$actual" != "$expected" ]; then
        echo "lockchain: checksum mismatch for $KEY_PATH; deferring to native prompts." >&2
        exit 0
    fi
fi

if ! zfs load-key -a; then
    echo "lockchain: zfs load-key -a failed; fallback to native prompts." >&2
fi
"#,
        label = token_label,
        mountpoint = mountpoint_str,
        key_path = key_path_str,
        checksum = checksum_str
    );

    fs::write(local_top_path, local_top_content)?;
    fs::set_permissions(local_top_path, fs::Permissions::from_mode(0o755))?;

    events.push(event(
        WorkflowLevel::Info,
        format!(
            "Initramfs-tools hook installed at {} and local-top script at {}.",
            hook_path.display(),
            local_top_path.display()
        ),
    ));
    Ok(())
}

/// Run the detected initramfs tool to pick up the new hook.
pub(crate) fn rebuild_initramfs(
    events: &mut Vec<WorkflowEvent>,
    flavor: InitramfsFlavor,
) -> LockchainResult<()> {
    match flavor {
        InitramfsFlavor::Dracut => {
            let args = [
                OsString::from("-f"),
                OsString::from("--add"),
                OsString::from("lockchain"),
            ];
            let output = run_external(DRACUT_BINARIES, &args)?;
            if output.status.success() {
                events.push(event(
                    WorkflowLevel::Success,
                    "Dracut rebuild completed with lockchain module added.",
                ));
                Ok(())
            } else {
                Err(LockchainError::Provider(format!(
                    "dracut -f --add lockchain failed with status {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim()
                )))
            }
        }
        InitramfsFlavor::InitramfsTools => {
            let output = run_external(UPDATE_INITRAMFS_BINARIES, &[OsString::from("-u")])?;
            if output.status.success() {
                events.push(event(
                    WorkflowLevel::Success,
                    "update-initramfs rebuild completed.",
                ));
                Ok(())
            } else {
                Err(LockchainError::Provider(format!(
                    "update-initramfs -u failed with status {:?}: {}",
                    output.status.code(),
                    String::from_utf8_lossy(&output.stderr).trim()
                )))
            }
        }
    }
}

/// Inspect the generated initramfs to ensure our assets were included.
fn audit_initramfs(
    events: &mut Vec<WorkflowEvent>,
    flavor: InitramfsFlavor,
) -> LockchainResult<()> {
    for candidate in LSINITRD_BINARIES {
        if Path::new(candidate).exists() {
            let output = Command::new(candidate)
                .output()
                .map_err(|err| LockchainError::Provider(err.to_string()))?;
            if !output.status.success() {
                continue;
            }
            let manifest = String::from_utf8_lossy(&output.stdout);
            let missing: Vec<&str> = match flavor {
                InitramfsFlavor::Dracut => {
                    ["lockchain-load-key.sh", "lockchain-load-key.service", "zfs-load-key.service.d/lockchain.conf", "run-lockchain.mount"]
                        .iter()
                        .copied()
                        .filter(|needle| !manifest.contains(needle))
                        .collect()
                }
                InitramfsFlavor::InitramfsTools => {
                    ["initramfs-tools/hooks/zz-lockchain", "initramfs-tools/scripts/local-top/lockchain"]
                        .iter()
                        .copied()
                        .filter(|needle| !manifest.contains(needle))
                        .collect()
                }
            };
            if missing.is_empty() {
                events.push(event(
                    WorkflowLevel::Success,
                    "Initramfs audit confirmed lockchain loader assets are present.",
                ));
                return Ok(());
            } else {
                let message = format!("Initramfs audit missing assets: {}", missing.join(", "));
                events.push(event(WorkflowLevel::Error, message.clone()));
                return Err(LockchainError::Provider(message));
            }
        }
    }
    events.push(event(
        WorkflowLevel::Warn,
        "lsinitrd not available; unable to audit initramfs contents.",
    ));
    Ok(())
}

/// Reinstall boot assets (dracut or initramfs-tools) and rebuild initramfs to keep loader state consistent.
pub(crate) fn repair_boot_assets(
    config: &LockchainConfig,
    events: &mut Vec<WorkflowEvent>,
) -> LockchainResult<()> {
    let datasets: Vec<String> = config
        .policy
        .datasets
        .iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    if datasets.is_empty() {
        events.push(event(
            WorkflowLevel::Error,
            "policy.datasets is empty; set at least one encryption root before staging initramfs assets.",
        ));
        return Err(LockchainError::InvalidConfig(
            "policy.datasets missing entries".into(),
        ));
    }

    let dest_path = config.key_hex_path();
    let key_filename = dest_path
        .file_name()
        .and_then(|os| os.to_str())
        .unwrap_or(&config.usb.device_key_path)
        .to_string();
    let mountpoint_path = dest_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| {
            PathBuf::from(STAGING_ROOT).join(
                config
                    .usb
                    .device_label
                    .as_deref()
                    .unwrap_or(LOCKCHAIN_LABEL),
            )
        });
    let mountpoint_str = mountpoint_path.to_string_lossy().into_owned();

    let flavor = detect_initramfs_flavor()?;
    match flavor {
        InitramfsFlavor::Dracut => install_dracut_module(
            &mountpoint_str,
            &dest_path,
            &key_filename,
            config.usb.expected_sha256.as_deref(),
            config.usb.device_uuid.as_deref(),
            &datasets,
            events,
        )?,
        InitramfsFlavor::InitramfsTools => install_initramfs_tools_hooks(
            &mountpoint_path,
            &dest_path,
            config.usb.expected_sha256.as_deref(),
            config
                .usb
                .device_label
                .as_deref()
                .unwrap_or(LOCKCHAIN_LABEL),
            events,
        )?,
    }
    rebuild_initramfs(events, flavor)?;
    audit_initramfs(events, flavor)
}

/// Details required to render the dracut hook for this deployment.
struct DracutContext {
    mountpoint: String,
    dest_path: String,
    key_filename: String,
    checksum: Option<String>,
    token_uuid: Option<String>,
    datasets: Vec<String>,
}

/// Represents the installed dracut module directory.
struct DracutModule {
    root: PathBuf,
}

impl DracutModule {
    /// Materialise the module files onto disk using the provided context.
    fn install(ctx: &DracutContext) -> LockchainResult<Self> {
        let module = determine_module_dir();
        fs::create_dir_all(&module)?;

        let script = module.join("lockchain-load-key.sh");
        let service = module.join("lockchain-load-key.service");
        let dropin_key_dir = module.join("zfs-load-key.service.d");
        let dropin_module_dir = module.join("zfs-load-module.service.d");
        let dropin_key = dropin_key_dir.join("lockchain.conf");
        let dropin_module = dropin_module_dir.join("lockchain.conf");
        let setup = module.join("module-setup.sh");
        let mount_unit = module.join("run-lockchain.mount");

        fs::create_dir_all(&dropin_key_dir)?;
        fs::create_dir_all(&dropin_module_dir)?;

        write_template(&script, LOCKCHAIN_LOAD_KEY_TEMPLATE, ctx, 0o750)?;
        write_template(&service, LOCKCHAIN_SERVICE_TEMPLATE, ctx, 0o644)?;
        write_template(&dropin_key, LOCKCHAIN_DROPIN_TEMPLATE, ctx, 0o644)?;
        write_template(&dropin_module, LOCKCHAIN_ZFS_DROPIN_TEMPLATE, ctx, 0o644)?;
        write_template(&setup, LOCKCHAIN_MODULE_SETUP_TEMPLATE, ctx, 0o750)?;
        write_template(&mount_unit, LOCKCHAIN_MOUNT_TEMPLATE, ctx, 0o644)?;

        Ok(Self { root: module })
    }
}

/// Pick a sane destination directory for the dracut module.
fn determine_module_dir() -> PathBuf {
    let candidates = [
        PathBuf::from("/usr/lib/dracut/modules.d/90lockchain"),
        PathBuf::from("/lib/dracut/modules.d/90lockchain"),
    ];

    for candidate in &candidates {
        if candidate.exists() {
            return candidate.clone();
        }
    }

    candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| PathBuf::from("/usr/lib/dracut/modules.d/90lockchain"))
}

/// Render a template to disk with executable or config permissions as needed.
fn write_template(
    path: &Path,
    template: &str,
    ctx: &DracutContext,
    mode: u32,
) -> LockchainResult<()> {
    let rendered = template
        .replace("{{TOKEN_LABEL}}", LOCKCHAIN_LABEL)
        .replace("{{MOUNTPOINT}}", &ctx.mountpoint)
        .replace("{{KEY_FILENAME}}", &ctx.key_filename)
        .replace("{{KEY_PATH}}", &ctx.dest_path)
        .replace(
            "{{KEY_SHA256}}",
            ctx.checksum.clone().unwrap_or_default().as_str(),
        )
        .replace(
            "{{KEY_UUID}}",
            ctx.token_uuid.clone().unwrap_or_default().as_str(),
        )
        .replace("{{DATASETS}}", ctx.datasets.join(" ").as_str())
        .replace("{{SERVICE_NAME}}", "lockchain-load-key.service")
        .replace("{{SCRIPT_NAME}}", "lockchain-load-key.sh")
        .replace("{{DROPIN_NAME}}", "lockchain.conf")
        .replace("{{DROPIN_DIR}}", "zfs-load-key.service.d")
        .replace("{{MODULE_DROPIN_DIR}}", "zfs-load-module.service.d")
        .replace("{{VERSION}}", env!("CARGO_PKG_VERSION"));

    fs::write(path, rendered)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

const LOCKCHAIN_LOAD_KEY_TEMPLATE: &str = include_str!("../../templates/lockchain-load-key.sh");
const LOCKCHAIN_SERVICE_TEMPLATE: &str = include_str!("../../templates/lockchain-load-key.service");
const LOCKCHAIN_DROPIN_TEMPLATE: &str = include_str!("../../templates/lockchain-load-key.conf");
const LOCKCHAIN_ZFS_DROPIN_TEMPLATE: &str =
    include_str!("../../templates/lockchain-zfs-load-module.conf");
const LOCKCHAIN_MODULE_SETUP_TEMPLATE: &str =
    include_str!("../../templates/lockchain-module-setup.sh");
const LOCKCHAIN_MOUNT_TEMPLATE: &str = include_str!("../../templates/run-lockchain.mount");
