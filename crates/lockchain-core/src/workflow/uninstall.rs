use super::{
    event,
    privilege::{run_external, CommandOutput},
    WorkflowEvent, WorkflowLevel, WorkflowReport,
};
use crate::config::LockchainConfig;
use crate::error::{LockchainError, LockchainResult};
use std::env;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

const SYSTEMD_DIR_ENV: &str = "LOCKCHAIN_SYSTEMD_DIR";
const SYSTEMCTL_PATH_ENV: &str = "LOCKCHAIN_SYSTEMCTL";
const RUN_DIR: &str = "/run/lockchain";
const STATE_DIR: &str = "/var/lib/lockchain";
const RM_BINARIES: &[&str] = &["/bin/rm", "/usr/bin/rm"];
const INSTALLED_BINARIES: &[&str] = &[
    "lockchain-cli",
    "lockchain-daemon",
    "lockchain-key-usb",
    "lockchain-ui",
];

/// Remove LockChain services, configuration, and cached key material from the host.
pub fn uninstall(config: &LockchainConfig) -> LockchainResult<WorkflowReport> {
    let mut events = Vec::new();

    if let Some(systemctl) = systemctl_path() {
        disable_unit(&systemctl, "lockchain-zfs.service", &mut events);
        disable_unit(&systemctl, "lockchain-key-usb.service", &mut events);
        disable_unit(&systemctl, "run-lockchain.mount", &mut events);

        for dataset in &config.policy.datasets {
            if let Some(unit) = escaped_dataset_unit(dataset) {
                disable_unit(&systemctl, &unit, &mut events);
            }
        }

        daemon_reload(&systemctl, &mut events);
    } else {
        events.push(event(
            WorkflowLevel::Warn,
            "systemctl not found; disable services manually if they remain active.",
        ));
    }

    let systemd_dir = systemd_dir();
    let mount_unit = systemd_dir.join("run-lockchain.mount");
    remove_file(&mount_unit, "Removed run-lockchain.mount unit", &mut events);

    for dataset in &config.policy.datasets {
        if let Some(unit) = escaped_dataset_unit(dataset) {
            let unit_path = systemd_dir.join(unit);
            remove_file(
                &unit_path,
                "Removed dataset-specific systemd unit",
                &mut events,
            );
        }
    }

    remove_dir(
        Path::new(STATE_DIR),
        "Purged /var/lib/lockchain state",
        &mut events,
    );

    let key_path = Path::new(&config.usb.key_hex_path);
    remove_file(
        key_path,
        "Deleted cached key material from host",
        &mut events,
    );

    let usb_key = Path::new(RUN_DIR).join(&config.usb.device_key_path);
    remove_file(
        &usb_key,
        "Removed key material from mounted USB token",
        &mut events,
    );

    for binary in INSTALLED_BINARIES {
        let local_path = Path::new("/usr/local/bin").join(binary);
        remove_file(
            &local_path,
            &format!("Removed installed binary {binary}"),
            &mut events,
        );

        let usr_bin = Path::new("/usr/bin").join(binary);
        if let Ok(meta) = fs::symlink_metadata(&usr_bin) {
            if meta.file_type().is_symlink() {
                if let Ok(target) = fs::read_link(&usr_bin) {
                    if target == local_path {
                        remove_symlink(
                            &usr_bin,
                            &format!("Removed /usr/bin symlink for {binary}"),
                            &mut events,
                        );
                    }
                } else {
                    remove_symlink(
                        &usr_bin,
                        &format!("Removed /usr/bin symlink for {binary}"),
                        &mut events,
                    );
                }
            }
        }
    }

    if config.path.exists() {
        match fs::remove_file(&config.path) {
            Ok(_) => events.push(event(
                WorkflowLevel::Success,
                format!("Removed configuration at {}", config.path.display()),
            )),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                match remove_file_privileged(&config.path) {
                    Ok(_) => events.push(event(
                        WorkflowLevel::Success,
                        format!("Removed configuration at {}", config.path.display()),
                    )),
                    Err(priv_err) => events.push(event(
                        WorkflowLevel::Warn,
                        format!(
                            "Failed to remove configuration {}: {priv_err}",
                            config.path.display()
                        ),
                    )),
                }
            }
            Err(err) => events.push(event(
                WorkflowLevel::Warn,
                format!(
                    "Failed to remove configuration {}: {err}",
                    config.path.display()
                ),
            )),
        }
    } else {
        events.push(event(
            WorkflowLevel::Info,
            format!("Configuration already absent at {}", config.path.display()),
        ));
    }

    Ok(WorkflowReport {
        title: "LockChain uninstall".into(),
        events,
        recovery_key: None,
    })
}

fn disable_unit(systemctl: &Path, unit: &str, events: &mut Vec<WorkflowEvent>) {
    match run_systemctl_privileged(systemctl, &["disable", "--now", unit]) {
        Ok(result) if result.status.success() => {
            events.push(event(WorkflowLevel::Info, format!("Disabled {unit}")))
        }
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            events.push(event(
                WorkflowLevel::Warn,
                format!("systemctl disable {unit} failed: {}", stderr.trim()),
            ));
        }
        Err(err) => events.push(event(
            WorkflowLevel::Warn,
            format!("systemctl disable {unit} failed: {err}"),
        )),
    }
}

fn daemon_reload(systemctl: &Path, events: &mut Vec<WorkflowEvent>) {
    match run_systemctl_privileged(systemctl, &["daemon-reload"]) {
        Ok(result) if result.status.success() => events.push(event(
            WorkflowLevel::Info,
            "systemd daemon reloaded after uninstall.",
        )),
        Ok(result) => {
            let stderr = String::from_utf8_lossy(&result.stderr);
            events.push(event(
                WorkflowLevel::Warn,
                format!("systemctl daemon-reload failed: {}", stderr.trim()),
            ));
        }
        Err(err) => events.push(event(
            WorkflowLevel::Warn,
            format!("systemctl daemon-reload failed: {err}"),
        )),
    }
}

fn remove_file(path: &Path, message: &str, events: &mut Vec<WorkflowEvent>) {
    if path.exists() {
        if path.is_file() {
            if let Ok(file) = OpenOptions::new().write(true).open(path) {
                let _ = file.set_len(0);
            }
        }
        match fs::remove_file(path) {
            Ok(_) => events.push(event(
                WorkflowLevel::Success,
                format!("{message}: {}", path.display()),
            )),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                match remove_file_privileged(path) {
                    Ok(_) => events.push(event(
                        WorkflowLevel::Success,
                        format!("{message}: {}", path.display()),
                    )),
                    Err(priv_err) => events.push(event(
                        WorkflowLevel::Warn,
                        format!("Failed to remove {}: {priv_err}", path.display()),
                    )),
                }
            }
            Err(err) => events.push(event(
                WorkflowLevel::Warn,
                format!("Failed to remove {}: {err}", path.display()),
            )),
        }
    }
}

fn remove_dir(path: &Path, message: &str, events: &mut Vec<WorkflowEvent>) {
    if path.exists() {
        match fs::remove_dir_all(path) {
            Ok(_) => events.push(event(
                WorkflowLevel::Success,
                format!("{message}: {}", path.display()),
            )),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                match remove_dir_privileged(path) {
                    Ok(_) => events.push(event(
                        WorkflowLevel::Success,
                        format!("{message}: {}", path.display()),
                    )),
                    Err(priv_err) => events.push(event(
                        WorkflowLevel::Warn,
                        format!("Failed to remove directory {}: {priv_err}", path.display()),
                    )),
                }
            }
            Err(err) => events.push(event(
                WorkflowLevel::Warn,
                format!("Failed to remove directory {}: {err}", path.display()),
            )),
        }
    }
}

fn remove_symlink(path: &Path, message: &str, events: &mut Vec<WorkflowEvent>) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            match fs::remove_file(path) {
                Ok(_) => events.push(event(
                    WorkflowLevel::Success,
                    format!("{message}: {}", path.display()),
                )),
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    match remove_file_privileged(path) {
                        Ok(_) => events.push(event(
                            WorkflowLevel::Success,
                            format!("{message}: {}", path.display()),
                        )),
                        Err(priv_err) => events.push(event(
                            WorkflowLevel::Warn,
                            format!("Failed to remove symlink {}: {priv_err}", path.display()),
                        )),
                    }
                }
                Err(err) => events.push(event(
                    WorkflowLevel::Warn,
                    format!("Failed to remove symlink {}: {err}", path.display()),
                )),
            }
        }
    }
}

fn systemctl_path() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os(SYSTEMCTL_PATH_ENV) {
        return Some(PathBuf::from(explicit));
    }
    for candidate in ["/bin/systemctl", "/usr/bin/systemctl"] {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn systemd_dir() -> PathBuf {
    env::var_os(SYSTEMD_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"))
}

fn escaped_dataset_unit(dataset: &str) -> Option<String> {
    if let Some(path) = systemd_escape_path() {
        if let Ok(output) = Command::new(path)
            .args(["--template=lockchain-zfs@.service", dataset])
            .output()
        {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }
    None
}

fn systemd_escape_path() -> Option<PathBuf> {
    for candidate in ["/bin/systemd-escape", "/usr/bin/systemd-escape"] {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn run_systemctl_privileged(systemctl: &Path, args: &[&str]) -> LockchainResult<CommandOutput> {
    let candidate = systemctl.to_string_lossy().into_owned();
    let os_args: Vec<OsString> = args.iter().map(|arg| OsString::from(*arg)).collect();
    run_external(&[candidate.as_str()], &os_args)
}

fn invoke_rm(path: &Path, recursive: bool) -> LockchainResult<()> {
    let flag = if recursive { "-rf" } else { "-f" };
    let args = vec![
        OsString::from(flag),
        OsString::from(path.to_string_lossy().into_owned()),
    ];
    let output = run_external(RM_BINARIES, &args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(LockchainError::Provider(format!(
            "rm {} {} failed: {}",
            flag,
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

fn remove_file_privileged(path: &Path) -> LockchainResult<()> {
    invoke_rm(path, false)
}

fn remove_dir_privileged(path: &Path) -> LockchainResult<()> {
    invoke_rm(path, true)
}
